package diagnostic

import (
	"strings"
	"testing"
)

// targetOrder is the full https probe order used to exercise the target-mode
// verdict branches.
var targetOrder = []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}

func TestDiagnoseTargetBranches(t *testing.T) {
	tg := mustTarget(t, "github.com")
	pass := ProbeResult{Status: StatusPass}
	skip := ProbeResult{Status: StatusSkip}
	fail := ProbeResult{Status: StatusFail}

	cases := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want string
	}{
		{
			name: "iface down short-circuits",
			res: map[ProbeID]ProbeResult{
				ProbeIface: fail, ProbeInternet: skip, ProbeDNS: skip,
				ProbeTargetTCP: skip, ProbeTLS: skip, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "link is down",
		},
		{
			name: "dns fails but general internet is up",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: fail,
				ProbeTargetTCP: skip, ProbeTLS: skip, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "general internet is reachable",
		},
		{
			name: "target unreachable but internet up",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: pass, ProbeHTTPS: skip,
			},
			want: "unreachable though DNS and the general internet work",
		},
		{
			name: "target and internet both unreachable",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: fail, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: fail, ProbeHTTPS: skip,
			},
			want: "local egress problem",
		},
		{
			name: "tls handshake fails",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: fail, ProbeHTTP: pass, ProbeHTTPS: skip,
			},
			want: "TLS handshake fails",
		},
		{
			name: "https blocked",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: pass, ProbeHTTP: pass, ProbeHTTPS: fail,
			},
			want: "no HTTPS response",
		},
		{
			name: "http blocked",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: pass, ProbeHTTP: fail, ProbeHTTPS: pass,
			},
			want: "HTTPS works but no HTTP response",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := Diagnose(tg, targetOrder, c.res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

// The banner-check verdict covers the SSH/SMTP protocol path.
func TestDiagnoseBannerFail(t *testing.T) {
	tg := mustTarget(t, "host:22")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeSSH}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass},
		ProbeSSH: {Status: StatusFail},
	}
	if v := Diagnose(tg, order, res); !strings.Contains(v, "banner check failed") {
		t.Errorf("got %q, want 'banner check failed'", v)
	}
}

// Generic mode: egress up but DNS down is a distinct, diagnosable state.
func TestDiagnoseGenericEgressNoDNS(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusFail},
		ProbeDNS: {Status: StatusPass},
	}
	if v := Diagnose(nil, order, res); !strings.Contains(v, "no direct TCP egress") {
		t.Errorf("got %q, want 'no direct TCP egress'", v)
	}
}
