package diagnostic

import (
	"context"
	"testing"
	"time"
)

// Availability smoke tests: the per-OS wrappers really run on the CI matrix.
// No default-route/WLAN assumptions — assert only that each returns without
// panic within its deadline and the output shape is sane. Cancellation/kill
// correctness is covered deterministically by the ui package's re-exec tests.

func TestDefaultRouteSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gw, found, err := defaultRoute(ctx)
	t.Logf("defaultRoute: gw=%q found=%v err=%v", gw, found, err)
	if found && gw == "" {
		t.Error("found a default route but the gateway is empty")
	}
}

func TestSSIDSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := ssid(ctx, "no-such-interface-0"); got != "" {
		t.Errorf("ssid on a nonexistent interface = %q, want empty", got)
	}
}

func TestFixHintsPerGOOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "plan9"} {
		if ifaceFix(goos) == "" || dnsFix(goos) == "" {
			t.Errorf("empty fix hint for %s", goos)
		}
	}
	if ifaceFix("darwin") == ifaceFix("windows") {
		t.Error("darwin and windows iface hints should differ")
	}
}
