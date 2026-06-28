package diagnostic

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestStatusString(t *testing.T) {
	cases := []struct {
		s    Status
		want string
	}{
		{StatusPass, "PASS"},
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

// dialIPs against a live loopback listener returns a connection pinned to the
// address that won, with the attempt recorded. Offline-safe (loopback only).
func TestDialIPsSuccess(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, sel, attempts, rtt := dialIPs(ctx, []net.IP{net.ParseIP("127.0.0.1")}, port)
	if conn == nil {
		t.Fatal("expected a connection to the loopback listener")
	}
	defer conn.Close()
	if !sel.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("selected = %v, want 127.0.0.1", sel)
	}
	if len(attempts) != 1 {
		t.Errorf("attempts = %d, want 1", len(attempts))
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want > 0", rtt)
	}
}

func TestDialIPsEmpty(t *testing.T) {
	conn, sel, attempts, rtt := dialIPs(context.Background(), nil, 80)
	if conn != nil || sel != nil || attempts != nil || rtt != 0 {
		t.Errorf("dialIPs(empty) = (%v,%v,%v,%v), want all zero", conn, sel, attempts, rtt)
	}
}

// A refused loopback port fails fast and deterministically: no conn, the failed
// attempt is recorded with its error.
func TestDialIPsRefused(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listening now → connection refused

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, attempts, _ := dialIPs(ctx, []net.IP{net.ParseIP("127.0.0.1")}, port)
	if conn != nil {
		conn.Close()
		t.Fatal("expected no connection to a closed port")
	}
	if len(attempts) != 1 || attempts[0].Err == nil {
		t.Errorf("want one failed attempt with an error, got %+v", attempts)
	}
}

// pathIdentity reads the winning conn's LocalAddr as ground truth.
func TestPathIdentityFromConn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	src, iface := pathIdentity(conn, net.ParseIP("127.0.0.1"), port)
	if src == nil || !src.IsLoopback() {
		t.Errorf("src = %v, want a loopback address", src)
	}
	if iface == "" {
		t.Error("iface should resolve for the loopback source")
	}
}

// ifaceForIP for an address assigned to no interface is an explicit unknown,
// never a guess. 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — never local.
func TestIfaceForIPUnknown(t *testing.T) {
	if got := ifaceForIP(net.ParseIP("203.0.113.213")); got != "(unknown iface)" {
		t.Errorf("ifaceForIP(unassigned) = %q, want '(unknown iface)'", got)
	}
}
