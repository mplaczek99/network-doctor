package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// silentConn simulates a server that accepts the connection but never sends a
// banner: every read fails immediately as a deadline timeout, so the test
// doesn't wait out the real 2s read deadline.
type silentConn struct{ fakeConn }

func (silentConn) Read([]byte) (int, error)        { return 0, os.ErrDeadlineExceeded }
func (silentConn) SetReadDeadline(time.Time) error { return nil }

// dialIPs never attempts more than maxAttempts addresses, no matter how many
// the resolver returned.
func TestDialIPsAttemptCap(t *testing.T) {
	calls := 0
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("connection refused")
	}}
	ips := make([]net.IP, maxAttempts+4)
	for i := range ips {
		ips[i] = net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1))
	}

	conn, _, attempts, _ := ops.dialIPs(context.Background(), ips, 80)
	if conn != nil {
		t.Fatal("expected no connection from the failing dialer")
	}
	if calls != maxAttempts || len(attempts) != maxAttempts {
		t.Errorf("calls = %d, attempts = %d, want %d each", calls, len(attempts), maxAttempts)
	}
}

// A cancelled context stops the address loop after the in-flight attempt
// instead of grinding through the remaining addresses.
func TestDialIPsCancelledStopsEarly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, context.Canceled
	}}
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")}

	conn, _, attempts, _ := ops.dialIPs(ctx, ips, 80)
	if conn != nil {
		t.Fatal("expected no connection under a cancelled context")
	}
	if len(attempts) != 1 {
		t.Errorf("attempts = %d, want 1 (loop must stop on cancel)", len(attempts))
	}
}

// DNS failure modes: resolver error and an empty (no A record) answer both
// fail with an actionable detail, never panic or pass.
func TestDNSProbeErrors(t *testing.T) {
	ops := &netops{lookupIP: func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("SERVFAIL")
	}}
	r := ops.dnsProbe("example.com", false, nil)(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "cannot resolve example.com") || r.Fix == "" {
		t.Errorf("lookup error = %+v, want FAIL with resolve detail and a fix", r)
	}

	ops.lookupIP = func(context.Context, string) ([]net.IP, error) { return nil, nil }
	r = ops.dnsProbe("example.com", false, nil)(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "no A record") {
		t.Errorf("empty answer = %+v, want FAIL with 'no A record'", r)
	}
}

// A TLS handshake error is a FAIL with the cleaned error in the detail and a
// fix hint — not a panic and not a skip.
func TestTLSProbeHandshakeFailure(t *testing.T) {
	ops := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("x509: certificate has expired")
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}

	r := ops.tlsProbe("example.com", 443)(context.Background(), deps)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "TLS handshake failed") ||
		!strings.Contains(r.Detail, "certificate has expired") || r.Fix == "" {
		t.Errorf("handshake failure = %+v, want FAIL with error detail and a fix", r)
	}
}

// A server that connects but never sends a banner is a WARN (the port
// answered, the service didn't) with the explicit no-banner detail, once the
// read deadline hits.
func TestBannerProbeReadTimeout(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return silentConn{}, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}

	r := ops.bannerProbe(ProbeSSH, "SSH banner", 22).Run(context.Background(), deps)
	if r.Status != StatusWarn || r.Detail != "connected, no banner within deadline" {
		t.Errorf("silent server = %+v, want WARN with no-banner detail", r)
	}
	if !r.SelectedIP.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("SelectedIP = %v, want the pinned dependency IP", r.SelectedIP)
	}
}

// Dependent probes fed an empty/zero dependency map degrade to their explicit
// fail/skip states — no nil-deref, no accidental pass.
func TestProbesMalformedDeps(t *testing.T) {
	ops := &netops{}
	empty := map[ProbeID]ProbeResult{}
	ctx := context.Background()

	if r := ops.targetTCPProbe(443)(ctx, empty); r.Status != StatusFail || !strings.Contains(r.Detail, "no resolved addresses") {
		t.Errorf("targetTCP without DNS result = %+v, want FAIL 'no resolved addresses'", r)
	}
	if r := ops.tlsProbe("example.com", 443)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("tls without pinned IP = %+v, want SKIP", r)
	}
	if r := ops.httpProbe(ProbeHTTP, "example.com", 80, "http", ProbeDNS)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("http without DNS addrs = %+v, want SKIP", r)
	}
	if r := ops.httpProbe(ProbeHTTPS, "example.com", 443, "https", ProbeTLS)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("https without TLS pinned IP = %+v, want SKIP", r)
	}
	if r := ops.bannerProbe(ProbeSSH, "SSH banner", 22).Run(ctx, empty); r.Status != StatusSkip {
		t.Errorf("banner without pinned IP = %+v, want SKIP", r)
	}
}

// A response whose headers blow past MaxResponseHeaderBytes fails the HTTP
// probe instead of buffering unbounded attacker-controlled bytes.
func TestHTTPProbeHeaderLimit(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			br := bufio.NewReader(server)
			for { // consume the HEAD request up to the blank line
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			// 128 KiB header, double the transport's 64 KiB cap.
			server.Write([]byte("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 128<<10) + "\r\n\r\n"))
		}()
		return client, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := ops.httpProbe(ProbeHTTP, "example.com", 80, "http", ProbeTargetTCP)(ctx, deps)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "no HTTP response") || !strings.Contains(r.Detail, "exceeded") {
		t.Errorf("oversized headers = %+v, want FAIL mentioning the exceeded header limit", r)
	}
}
