package ui

import (
	"net"
	"testing"
)

func mustTarget(t *testing.T, s string) *Target {
	t.Helper()
	target, err := parseTarget(s)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", s, err)
	}
	return target
}

// Generic mode: egress and DNS are siblings — an egress failure must not skip
// DNS, so DNS-down-but-internet-up remains diagnosable.
func TestSiblingIndependence(t *testing.T) {
	m := newModel(nil)
	m.results[pIface] = ProbeResult{ID: pIface, Status: StatusPass}
	m.started[pIface] = true
	cmds := m.scheduleStep()
	if len(cmds) != 2 {
		t.Fatalf("want 2 dispatched (internet, dns), got %d", len(cmds))
	}
	if !m.started[pInternet] || !m.started[pDNS] {
		t.Fatal("internet+dns should both be dispatched")
	}
	if _, ok := m.results[pDNS]; ok {
		t.Error("dns must be dispatched, not skipped by an egress failure")
	}
}

func TestSkipPropagation(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.results[pIface] = ProbeResult{Status: StatusPass}
	m.results[pInternet] = ProbeResult{Status: StatusPass}
	m.results[pDNS] = ProbeResult{Status: StatusFail}
	m.started[pIface], m.started[pInternet], m.started[pDNS] = true, true, true
	m.scheduleStep()
	if m.results[pTargetTCP].Status != StatusSkip {
		t.Fatalf("target_tcp = %v, want Skip", m.results[pTargetTCP].Status)
	}
	if m.results[pTLS].Status != StatusSkip || m.results[pHTTP].Status != StatusSkip {
		t.Error("skip must propagate through TLS and HTTP")
	}
}

func TestNADoesNotBlock(t *testing.T) {
	m := newModel(mustTarget(t, "1.1.1.1"))
	m.results[pIface] = ProbeResult{Status: StatusPass}
	m.results[pInternet] = ProbeResult{Status: StatusPass}
	m.results[pDNS] = ProbeResult{Status: StatusNA, Addrs: []net.IP{net.ParseIP("1.1.1.1")}}
	m.started[pIface], m.started[pInternet], m.started[pDNS] = true, true, true
	m.scheduleStep()
	if _, ok := m.results[pTargetTCP]; ok {
		t.Fatal("an NA dependency must not skip target_tcp")
	}
	if !m.started[pTargetTCP] {
		t.Fatal("target_tcp should be dispatched after an NA dependency")
	}
}
