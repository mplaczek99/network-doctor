package diagnostic

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn is a no-network net.Conn stand-in; only LocalAddr and Close are
// used by the code under test.
type fakeConn struct {
	net.Conn
	local net.Addr
}

func (c fakeConn) LocalAddr() net.Addr { return c.local }
func (fakeConn) Close() error          { return nil }

func TestStatusString(t *testing.T) {
	cases := []struct {
		s    Status
		want string
	}{
		{StatusPass, "PASS"},
		{StatusWarn, "WARN"},
		{StatusFail, "FAIL"},
		{StatusSkip, "SKIP"},
		{StatusNA, "N/A"},
		{Status(255), "?"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Status(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestJoinIPs(t *testing.T) {
	if got := joinIPs(nil); got != "" {
		t.Errorf("joinIPs(nil) = %q, want empty", got)
	}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	if got := joinIPs(ips); got != "1.1.1.1, 8.8.8.8" {
		t.Errorf("joinIPs = %q, want '1.1.1.1, 8.8.8.8'", got)
	}
}

// BuildProbes shapes for the http and smtp protocol paths (the ssh/https paths
// are covered in checks_test.go).
func TestBuildProbesProtoShapes(t *testing.T) {
	cases := []struct {
		target string
		want   int // iface, internet, dns, target_tcp, + protocol rows
	}{
		{"http://example.com", 5}, // + http
		{"host:25", 5},            // + smtp banner
		{"host:587", 5},           // + smtp banner
		{"host:9999", 4},          // ProtoNone — stops at target_tcp
	}
	for _, c := range cases {
		if got := len(BuildProbes(mustTarget(t, c.target))); got != c.want {
			t.Errorf("BuildProbes(%q) = %d probes, want %d", c.target, got, c.want)
		}
	}
}

// dialIPs with a stubbed dialer returns a connection pinned to the address
// that won, with the attempt recorded. No real sockets.
func TestDialIPsSuccess(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(time.Millisecond) // make the recorded RTT observable
		return fakeConn{}, nil
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, sel, attempts, rtt := ops.dialIPs(ctx, []net.IP{net.ParseIP("192.0.2.1")}, 80)
	if conn == nil {
		t.Fatal("expected a connection from the stub dialer")
	}
	defer conn.Close()
	if !sel.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("selected = %v, want 192.0.2.1", sel)
	}
	if len(attempts) != 1 {
		t.Errorf("attempts = %d, want 1", len(attempts))
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want > 0", rtt)
	}
}

func TestDialIPsEmpty(t *testing.T) {
	conn, sel, attempts, rtt := defaultOps.dialIPs(context.Background(), nil, 80)
	if conn != nil || sel != nil || attempts != nil || rtt != 0 {
		t.Errorf("dialIPs(empty) = (%v,%v,%v,%v), want all zero", conn, sel, attempts, rtt)
	}
}

// A refused dial fails deterministically: no conn, the failed attempt is
// recorded with its error.
func TestDialIPsRefused(t *testing.T) {
	errRefused := errors.New("connection refused")
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errRefused
	}}

	conn, _, attempts, _ := ops.dialIPs(context.Background(), []net.IP{net.ParseIP("192.0.2.1")}, 80)
	if conn != nil {
		conn.Close()
		t.Fatal("expected no connection from the failing dialer")
	}
	if len(attempts) != 1 || !errors.Is(attempts[0].Err, errRefused) {
		t.Errorf("want one failed attempt with the dialer's error, got %+v", attempts)
	}
}

// pathIdentity reads the winning conn's LocalAddr as ground truth and maps it
// back to an interface via the stubbed interface list.
func TestPathIdentityFromConn(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0"}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
	conn := fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 40000}}

	src, iface := ops.pathIdentity(context.Background(), conn, net.ParseIP("192.0.2.1"), 80)
	if !src.Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("src = %v, want 192.0.2.7", src)
	}
	if iface != "fake0" {
		t.Errorf("iface = %q, want fake0", iface)
	}
}

// ifaceForIP for an address assigned to no interface is an explicit unknown,
// never a guess. 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — never local.
func TestIfaceForIPUnknown(t *testing.T) {
	if got := defaultOps.ifaceForIP(net.ParseIP("203.0.113.213")); got != "(unknown iface)" {
		t.Errorf("ifaceForIP(unassigned) = %q, want '(unknown iface)'", got)
	}
}

// Probes run against stubbed netops: no real network, DNS, or OS interface
// access — the point of the function-field seam.
func TestNetopsInjection(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
		ssid: func(context.Context, string) string { return "FakeNet" },
	}

	r := ops.ifaceProbe(context.Background(), nil)
	if r.Status != StatusPass || r.Iface != "fake0" || r.Network != "FakeNet" {
		t.Errorf("ifaceProbe with stubs = %+v, want PASS on fake0/FakeNet", r)
	}

	r = ops.dnsProbe("example.com", false, nil)(context.Background(), nil)
	if r.Status != StatusPass || len(r.Addrs) != 1 || !r.Addrs[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("dnsProbe with stubs = %+v, want PASS with 192.0.2.1", r)
	}
}

// Degraded-but-functional dials downgrade to WARN: high latency, sibling
// address failures before a win, and an ambiguous source interface. A clean
// fast dial stays PASS.
func TestApplyDialWarnings(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	cases := []struct {
		name     string
		attempts []Attempt
		rtt      time.Duration
		iface    string
		want     Status
		note     string
	}{
		{"clean", []Attempt{{IP: ip}}, 10 * time.Millisecond, "eth0", StatusPass, ""},
		{"high latency", []Attempt{{IP: ip}}, warnRTT, "eth0", StatusWarn, "high latency"},
		{"partial addresses", []Attempt{{IP: ip, Err: errors.New("refused")}, {IP: ip}}, 10 * time.Millisecond, "eth0", StatusWarn, "1 of 2 address(es) failed"},
		{"ambiguous iface", []Attempt{{IP: ip}}, 10 * time.Millisecond, "(ambiguous)", StatusWarn, "ambiguous source interface"},
	}
	for _, c := range cases {
		r := ProbeResult{Status: StatusPass, Attempts: c.attempts, Iface: c.iface, Detail: "connected"}
		applyDialWarnings(&r, c.rtt)
		if r.Status != c.want {
			t.Errorf("%s: status = %v, want %v", c.name, r.Status, c.want)
		}
		if c.note != "" && !strings.Contains(r.Detail, c.note) {
			t.Errorf("%s: detail = %q, want it to mention %q", c.name, r.Detail, c.note)
		}
	}
}

// DowngradeEgress turns a direct-egress FAIL into WARN only when another path
// proved the network works: target TCP when a target exists, else DNS.
func TestDowngradeEgress(t *testing.T) {
	cases := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want Status
	}{
		{"generic dns works", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass},
		}, StatusWarn},
		{"generic dns fails too", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusFail},
		}, StatusFail},
		{"target tcp works", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass},
		}, StatusWarn},
		{"target tcp fails, dns pass not enough", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusFail},
		}, StatusFail},
		{"egress passing untouched", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusPass}, ProbeDNS: {Status: StatusPass},
		}, StatusPass},
	}
	for _, c := range cases {
		DowngradeEgress(c.res)
		if got := c.res[ProbeInternet].Status; got != c.want {
			t.Errorf("%s: internet status = %v, want %v", c.name, got, c.want)
		}
	}
}
