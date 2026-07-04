//go:build integration

package diagnostic

// Real-socket tests, kept out of the unit suite. Run with:
//
//	go test -tags integration ./internal/diagnostic
//
// Offline-safe: loopback only.

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// dialIPs against a live loopback listener returns a connection pinned to the
// address that won, with the attempt recorded.
func TestDialIPsLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, sel, attempts, rtt := defaultOps.dialIPs(ctx, []net.IP{net.ParseIP("127.0.0.1")}, port)
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

// A refused loopback port fails fast and deterministically: no conn, the failed
// attempt is recorded with its error.
func TestDialIPsRefusedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listening now → connection refused

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, attempts, _ := defaultOps.dialIPs(ctx, []net.IP{net.ParseIP("127.0.0.1")}, port)
	if conn != nil {
		conn.Close()
		t.Fatal("expected no connection to a closed port")
	}
	if len(attempts) != 1 || attempts[0].Err == nil {
		t.Errorf("want one failed attempt with an error, got %+v", attempts)
	}
}

// pathIdentity reads a real winning conn's LocalAddr as ground truth.
func TestPathIdentityLoopback(t *testing.T) {
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

	src, iface := defaultOps.pathIdentity(context.Background(), conn, net.ParseIP("127.0.0.1"), port)
	if src == nil || !src.IsLoopback() {
		t.Errorf("src = %v, want a loopback address", src)
	}
	if iface == "" {
		t.Error("iface should resolve for the loopback source")
	}
}
