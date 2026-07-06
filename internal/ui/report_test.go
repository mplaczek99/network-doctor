package ui

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mplaczek99/network-doctor/internal/diagnostic"
)

func TestReportSanitized(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: "ok"}
	}
	m.results[m.probes[0].ID] = diagnostic.ProbeResult{
		ID:     m.probes[0].ID,
		Status: diagnostic.StatusFail,
		Detail: "boom \x1b[31mred\x1b[0m",
		Fix:    "restart \x1b]0;evil\x07it",
		Attempts: []diagnostic.Attempt{
			{IP: net.ParseIP("93.184.216.34"), Dur: 12 * time.Millisecond, Err: errors.New("\x1b[2Jrefused")},
		},
	}
	m.facts = []Fact{{"http_code", "200\x1b[31m"}}
	m.jobDisplay = "curl https://example.com"

	rep := m.report()
	for _, want := range []string{
		"target: example.com:443",
		"verdict: FAIL",
		"boom red",
		"fix: restart it",
		"attempt: 93.184.216.34 12ms refused",
		"http_code: 200",
		"curl https://example.com",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report missing %q\n%s", want, rep)
		}
	}
	if strings.ContainsRune(rep, 0x1b) {
		t.Errorf("escape byte leaked into report:\n%q", rep)
	}
}

func TestReportVerdictPass(t *testing.T) {
	m := newModel(nil)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	rep := m.report()
	if !strings.Contains(rep, "verdict: PASS") || !strings.Contains(rep, "target: none") {
		t.Errorf("bad generic pass report:\n%s", rep)
	}
}
