// Table tests for Diagnose verdicts: generic and targeted runs, proxy-only
// networks, and the in-progress placeholder.

package diagnostic

import (
	"strings"
	"testing"
)

func TestDiagnoseGeneric(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	cases := []struct {
		name          string
		internet, dns Status
		want          string
	}{
		{"online", StatusPass, StatusPass, "Online"},
		{"dns down", StatusPass, StatusFail, "DNS resolution is failing"},
		{"no egress", StatusFail, StatusPass, "no direct TCP egress"},
		{"offline", StatusFail, StatusFail, "Offline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {Status: StatusPass},
				ProbeInternet: {Status: c.internet},
				ProbeDNS:      {Status: c.dns},
			}
			if v := Diagnose(nil, order, res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

// Direct and proxied egress are diagnosed separately: a proxy-only network
// reads as online-via-proxy, and a dead configured proxy is called out even
// when direct connectivity works.
func TestDiagnoseProxy(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	cases := []struct {
		name                 string
		internet, proxy, dns Status
		downgraded           bool
		want                 string
	}{
		{"proxy-only network", StatusWarn, StatusPass, StatusPass, true, "Online via the environment proxy"},
		{"degraded direct with proxy", StatusWarn, StatusPass, StatusPass, false, "Online but degraded"},
		{"proxy dead, direct fine", StatusPass, StatusFail, StatusPass, false, "proxy is unreachable"},
		{"no proxy configured", StatusPass, StatusNA, StatusPass, false, "Online — direct TCP egress"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {Status: StatusPass},
				ProbeInternet: {Status: c.internet, downgraded: c.downgraded},
				ProbeProxy:    {Status: c.proxy},
				ProbeDNS:      {Status: c.dns},
			}
			if v := Diagnose(nil, order, res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

func TestDiagnoseTargetProxyOnly(t *testing.T) {
	tg := mustTarget(t, "host:9999")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusFail},
		ProbeProxy: {Status: StatusPass}, ProbeDNS: {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusFail},
	}
	DowngradeEgress(res)
	if v := Diagnose(tg, order, res); !strings.Contains(v, "proxy-only network") {
		t.Errorf("got %q, want a proxy-only verdict", v)
	}
	res[ProbeInternet] = ProbeResult{Status: StatusWarn}
	res[ProbeTargetTCP] = ProbeResult{Status: StatusPass}
	if v := Diagnose(tg, order, res); !strings.Contains(v, "direct internet egress is degraded") {
		t.Errorf("got %q, want a degraded direct-egress verdict", v)
	}
}

func TestDiagnoseIncomplete(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}}
	if v := Diagnose(nil, order, res); !strings.Contains(v, "Running") {
		t.Errorf("incomplete should report running, got %q", v)
	}
}

func TestDiagnoseTarget(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}

	// DNS + internet OK, Target TCP fails → remote port/firewall verdict.
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusFail},
		ProbeTLS: {Status: StatusSkip}, ProbeHTTP: {Status: StatusPass}, ProbeHTTPS: {Status: StatusSkip},
	}
	if v := Diagnose(tg, order, res); !strings.Contains(v, "unreachable") {
		t.Errorf("got %q, want 'unreachable'", v)
	}

	// Everything passes → Diagnose owns the shared all-clear verdict.
	for _, id := range order {
		res[id] = ProbeResult{Status: StatusPass}
	}
	if v := Diagnose(tg, order, res); !strings.Contains(v, "github.com:443 looks healthy") {
		t.Errorf("got %q, want target healthy verdict", v)
	}

	// A raw egress failure must never fall through to the all-clear verdict.
	res[ProbeInternet] = ProbeResult{Status: StatusFail}
	if v := Diagnose(tg, order, res); !strings.Contains(v, "direct internet egress is blocked") {
		t.Errorf("got %q, want blocked-egress verdict", v)
	}
}
