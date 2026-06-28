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
	if got := len(BuildProbes(nil)); got != 3 {
		t.Errorf("generic probes = %d, want 3", got)
	}
	if got := len(BuildProbes(mustTarget(t, "github.com"))); got != 6 {
		t.Errorf("https target probes = %d, want 6", got)
	}
	if got := len(BuildProbes(mustTarget(t, "host:22"))); got != 5 {
		t.Errorf("ssh target probes = %d, want 5", got)
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
