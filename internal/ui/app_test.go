package ui

import (
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// New wires the model and ExitCode reads it back. Toolbox mode with no chain run
// exits 0 through the public surface.
func TestNewAndExitCode(t *testing.T) {
	app := New(nil, true)
	if ExitCode(app) != 0 {
		t.Error("toolbox app with no chain run must ExitCode 0")
	}

	tg, _ := diagnostic.ParseTarget("github.com")
	if New(tg, false) == nil {
		t.Error("New must return a model for a target")
	}
}

// Toolbox Init emits one tick, then sleeps until the deferred chain is started.
func TestInit(t *testing.T) {
	if newModel(nil, false).Init() == nil {
		t.Error("normal Init must return a cmd")
	}
	tb := newModel(nil, true)
	cmd := tb.Init()
	if cmd == nil {
		t.Error("toolbox Init must still return the spinner tick")
	}
	_, next := tb.Update(cmd())
	if next != nil {
		t.Error("idle toolbox spinner tick must not rearm")
	}
	tb.doRestart()
	if !tb.spinnerActive() {
		t.Error("toolbox spinner must activate when the deferred chain starts")
	}
}
