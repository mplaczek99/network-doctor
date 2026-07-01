package diagnostic

import (
	"strings"
	"testing"
)

const darwinRouteFixture = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

func TestParseDarwinRoute(t *testing.T) {
	gw, found, err := parseDarwinRoute(strings.NewReader(darwinRouteFixture))
	if err != nil || !found || gw != "192.168.1.1" {
		t.Errorf("got (%q, %v, %v), want (192.168.1.1, true, nil)", gw, found, err)
	}

	// link#N and non-IP gateways are rejected, not returned.
	linkGw := "    gateway: link#12\n  interface: en0\n"
	if gw, found, err := parseDarwinRoute(strings.NewReader(linkGw)); found || gw != "" || err != nil {
		t.Errorf("link#N gateway: got (%q, %v, %v), want empty/false/nil", gw, found, err)
	}

	// No gateway line at all (e.g. "route: writing to routing socket" errors).
	if _, found, err := parseDarwinRoute(strings.NewReader("not routing output\n")); found || err != nil {
		t.Errorf("no gateway line: found=%v err=%v, want false/nil", found, err)
	}
}

// Fixture includes an Interface List, two active default routes (different
// metrics), On-link rows, and a competing *persistent* default route whose
// four-column shape must be structurally excluded (Codex round 3).
const windowsRouteFixture = `===========================================================================
Interface List
 12...aa bb cc dd ee ff ......Intel(R) Ethernet Connection
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.23     25
          0.0.0.0          0.0.0.0         10.0.0.1       10.0.0.99     50
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link      192.168.1.23    281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       172.16.0.1       1
===========================================================================
`

func TestParseWindowsRoute(t *testing.T) {
	gw, found, err := parseWindowsRoute(strings.NewReader(windowsRouteFixture))
	if err != nil || !found {
		t.Fatalf("got (%q, %v, %v), want a route", gw, found, err)
	}
	// Lowest metric among the five-column active rows wins; the persistent
	// default (metric 1, four columns) must never be selected.
	if gw != "192.168.1.1" {
		t.Errorf("gateway = %q, want 192.168.1.1 (lowest active metric, not persistent)", gw)
	}

	// No default route present.
	noDefault := "        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n"
	if gw, found, err := parseWindowsRoute(strings.NewReader(noDefault)); found || gw != "" || err != nil {
		t.Errorf("no default: got (%q, %v, %v), want empty/false/nil", gw, found, err)
	}
}
