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

	// Everything passes → the probe rows are sufficient; no redundant summary.
	for _, id := range order {
		res[id] = ProbeResult{Status: StatusPass}
	}
	if v := Diagnose(tg, order, res); v != "" {
		t.Errorf("got %q, want no redundant success verdict", v)
	}
}
