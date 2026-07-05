package diagnostic

import (
	"context"
	"testing"
)

func staticProbe(id ProbeID, deps []ProbeID, status Status) Probe {
	return Probe{ID: id, Name: string(id), Deps: deps, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		return ProbeResult{Status: status}
	}}
}

func TestRunAll(t *testing.T) {
	probes := []Probe{
		staticProbe("a", nil, StatusPass),
		staticProbe("b", []ProbeID{"a"}, StatusFail),
		staticProbe("c", []ProbeID{"b"}, StatusPass), // must be skipped: b failed
		staticProbe("d", []ProbeID{"a"}, StatusPass),
	}
	res := RunAll(context.Background(), probes)
	if len(res) != len(probes) {
		t.Fatalf("got %d results, want %d", len(res), len(probes))
	}
	want := map[ProbeID]Status{"a": StatusPass, "b": StatusFail, "c": StatusSkip, "d": StatusPass}
	for id, st := range want {
		if res[id].Status != st {
			t.Errorf("probe %s = %v, want %v", id, res[id].Status, st)
		}
	}
	if res["c"].ID != "c" {
		t.Errorf("skip result ID = %q, want c", res["c"].ID)
	}
}

func TestRunAllDowngradesEgress(t *testing.T) {
	probes := []Probe{
		staticProbe(ProbeIface, nil, StatusPass),
		staticProbe(ProbeInternet, []ProbeID{ProbeIface}, StatusFail),
		staticProbe(ProbeDNS, []ProbeID{ProbeIface}, StatusPass),
	}
	res := RunAll(context.Background(), probes)
	if res[ProbeInternet].Status != StatusWarn {
		t.Errorf("internet = %v, want WARN (DNS path works)", res[ProbeInternet].Status)
	}
}
