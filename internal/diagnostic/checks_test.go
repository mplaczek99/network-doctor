package diagnostic

import (
	"context"
	"testing"
	"time"
)

func mustTarget(t *testing.T, s string) *Target {
	t.Helper()
	tg, err := ParseTarget(s)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", s, err)
	}
	return tg
}

func TestBuildProbesShape(t *testing.T) {
	if got := len(BuildProbes(nil)); got != 4 {
		t.Errorf("generic probes = %d, want 4", got)
	}
	if got := len(BuildProbes(mustTarget(t, "github.com"))); got != 8 {
		t.Errorf("https target probes = %d, want 8", got)
	}
	if got := len(BuildProbes(mustTarget(t, "host:22"))); got != 6 {
		t.Errorf("ssh target probes = %d, want 6", got)
	}
}

func TestBuildProbesNamesProtocolApplicationRow(t *testing.T) {
	https := BuildProbes(mustTarget(t, "https://example.com"))
	want := []struct {
		id   ProbeID
		name string
		dep  ProbeID
	}{
		{id: ProbeTLS, name: "TLS example.com", dep: ProbeTargetTCP},
		{id: ProbeHTTP, name: "HTTP example.com", dep: ProbeDNS},
		{id: ProbeHTTPS, name: "HTTPS example.com", dep: ProbeTLS},
	}
	for i, tt := range want {
		got := https[len(https)-len(want)+i]
		if got.ID != tt.id || got.Name != tt.name {
			t.Errorf("probe %d = (%q, %q), want (%q, %q)", i, got.ID, got.Name, tt.id, tt.name)
		}
		if len(got.Deps) != 1 || got.Deps[0] != tt.dep {
			t.Errorf("probe %s deps = %v, want [%s]", got.ID, got.Deps, tt.dep)
		}
	}

	http := BuildProbes(mustTarget(t, "http://example.com"))
	got := http[len(http)-1]
	if got.ID != ProbeHTTP || got.Name != "HTTP example.com" || len(got.Deps) != 1 || got.Deps[0] != ProbeTargetTCP {
		t.Errorf("plain HTTP application probe = %+v, want HTTP depending on target TCP", got)
	}
}

func TestRemaining(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if d := remaining(ctx); d <= 0 || d > 2*time.Second {
		t.Errorf("remaining = %v, want (0,2s]", d)
	}
	if d := remaining(context.Background()); d != ProbeTimeout {
		t.Errorf("remaining(no deadline) = %v, want %v", d, ProbeTimeout)
	}
}
