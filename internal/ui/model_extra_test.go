package ui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// asModelP tolerates either a value model or a *model — the deferred-action path
// returns the latter (runPending has a pointer receiver).
func asModelP(t *testing.T, m tea.Model) model {
	t.Helper()
	switch v := m.(type) {
	case model:
		return v
	case *model:
		return *v
	default:
		t.Fatalf("expected model/*model, got %T", m)
		return model{}
	}
}

// ---- pure helpers ----

func TestTail(t *testing.T) {
	lines := []string{"a", "b", "c", "d"}
	if got := tail(lines, 2); len(got) != 2 || got[0] != "c" || got[1] != "d" {
		t.Errorf("tail(_,2) = %v, want [c d]", got)
	}
	if got := tail(lines, 10); len(got) != 4 {
		t.Errorf("tail bigger than slice = %v, want all 4", got)
	}
	if got := tail(nil, 3); got != nil {
		t.Errorf("tail(nil) = %v, want nil", got)
	}
}

func TestAppendCapped(t *testing.T) {
	var lines []string
	for i := 0; i < maxJobLines+50; i++ {
		lines = appendCapped(lines, "x")
	}
	if len(lines) != maxJobLines {
		t.Errorf("len = %d, want cap %d", len(lines), maxJobLines)
	}
	// The oldest lines are dropped, newest retained.
	lines = appendCapped(lines, "newest")
	if lines[len(lines)-1] != "newest" {
		t.Error("most recent line must be kept")
	}
	if len(lines) != maxJobLines {
		t.Errorf("len after overflow = %d, want %d", len(lines), maxJobLines)
	}
}

func TestTargetHost(t *testing.T) {
	if got := targetHost(nil); got != "" {
		t.Errorf("targetHost(nil) = %q, want empty", got)
	}
	if got := targetHost(mustTarget(t, "github.com")); got != "github.com" {
		t.Errorf("targetHost = %q, want github.com", got)
	}
}

func TestSchemeFor(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"http://example.com", "http"},
		{"https://example.com", "https"},
		{"example.com:22", "https"}, // non-http proto defaults to https
	}
	for _, c := range cases {
		if got := schemeFor(mustTarget(t, c.target)); got != c.want {
			t.Errorf("schemeFor(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}

func TestNetworkLine(t *testing.T) {
	m := newModel(nil)
	if got := m.networkLine(); got != "" {
		t.Errorf("no iface result → %q, want empty", got)
	}
	m.results[pIface] = ProbeResult{Status: StatusPass, Network: "HomeWiFi"}
	if got := m.networkLine(); got != "Wi-Fi: HomeWiFi" {
		t.Errorf("wifi line = %q", got)
	}
	m.results[pIface] = ProbeResult{Status: StatusPass, Iface: "eth0"}
	if got := m.networkLine(); got != "Wired: eth0" {
		t.Errorf("wired line = %q", got)
	}
	m.results[pIface] = ProbeResult{Status: StatusFail, Iface: "eth0"}
	if got := m.networkLine(); got != "" {
		t.Errorf("failed iface → %q, want empty", got)
	}
}

func TestGlyph(t *testing.T) {
	m := newModel(nil)
	// No result yet → spinner view, must not panic and must be non-empty handling.
	_ = m.glyph(pIface)
	cases := []struct {
		status Status
		want   rune
	}{
		{StatusPass, '✓'},
		{StatusFail, '✗'},
		{StatusSkip, '⊘'},
		{StatusNA, '–'},
	}
	for _, c := range cases {
		m.results[pIface] = ProbeResult{Status: c.status}
		if got := m.glyph(pIface); !strings.ContainsRune(got, c.want) {
			t.Errorf("glyph(%d) = %q, want to contain %q", c.status, got, c.want)
		}
	}
}

func TestJobStatusString(t *testing.T) {
	cases := []struct {
		s    JobStatus
		want string
	}{
		{JobQueued, "queued"},
		{JobRunning, "running"},
		{JobDone, "done"},
		{JobFailed, "failed"},
		{JobCanceled, "canceled"},
		{JobTimedOut, "timed out"},
		{JobStatus(99), "?"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("JobStatus(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}

// classifyJob is success-wins, then consults the context cause only on error.
func TestClassifyJob(t *testing.T) {
	if got := classifyJob(context.Background(), nil); got != JobDone {
		t.Errorf("nil err = %v, want JobDone", got)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classifyJob(cctx, errors.New("x")); got != JobCanceled {
		t.Errorf("canceled ctx = %v, want JobCanceled", got)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer dcancel()
	<-dctx.Done()
	if got := classifyJob(dctx, errors.New("x")); got != JobTimedOut {
		t.Errorf("deadline ctx = %v, want JobTimedOut", got)
	}
	if got := classifyJob(context.Background(), errors.New("boom")); got != JobFailed {
		t.Errorf("plain err = %v, want JobFailed", got)
	}
}

func TestExtractFactsNone(t *testing.T) {
	if got := extractFacts("unknown-key", []string{"anything"}); got != nil {
		t.Errorf("unknown tool key → %v, want nil", got)
	}
	if got := extractFacts("c", []string{"only three fields"}); got != nil {
		t.Errorf("malformed curl line → %v, want nil", got)
	}
}

// ---- tool construction ----

// toolsFor builds the curl argv with the right URL (scheme + explicit port) and
// sets LC_ALL=C via env, never as an argv token.
func TestToolBuildCurl(t *testing.T) {
	tg := mustTarget(t, "https://example.com:8443")
	var curl Tool
	for _, tl := range toolsFor(tg) {
		if tl.Key == "c" {
			curl = tl
		}
	}
	if curl.Key == "" {
		t.Fatal("curl tool not offered for an https target")
	}
	args, env, display := curl.Build(tg)
	if !strings.Contains(display, "https://example.com:8443") {
		t.Errorf("display = %q, want the explicit-port https URL", display)
	}
	if args[len(args)-1] != "https://example.com:8443" {
		t.Errorf("last arg = %q, want the URL", args[len(args)-1])
	}
	if !containsEnv(env, "LC_ALL=C") {
		t.Error("curl must set LC_ALL=C in env, not argv")
	}
}

func TestToolBuildPingHost(t *testing.T) {
	tg := mustTarget(t, "example.com")
	var ping Tool
	for _, tl := range toolsFor(tg) {
		if tl.Key == "p" {
			ping = tl
		}
	}
	args, _, _ := ping.Build(tg)
	if args[len(args)-1] != "example.com" {
		t.Errorf("ping last arg = %q, want host", args[len(args)-1])
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// ---- message routing & deferred actions ----

// 'q' while a job runs cancels it and defers the quit; the terminal event then
// performs it.
func TestDeferredQuit(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.generation = 3
	canceled := false
	m.activeJob = &job{id: "j", gen: 3, cancel: func() { canceled = true }}

	u, cmd := m.Update(keyMsg("q"))
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendQuit {
		t.Fatal("q during a job must defer a quit")
	}
	if !canceled {
		t.Error("the active job must be canceled")
	}
	if cmd != nil {
		t.Error("deferred quit must not quit immediately")
	}

	u2, cmd2 := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModelP(t, u2)
	if nm2.activeJob != nil {
		t.Error("active job must clear on the terminal event")
	}
	if cmd2 == nil {
		t.Fatal("terminal event must run the deferred quit")
	}
	if _, ok := cmd2().(tea.QuitMsg); !ok {
		t.Errorf("deferred quit cmd = %T, want tea.QuitMsg", cmd2())
	}
}

// 'r' while a job runs defers a rerun; the terminal event bumps the generation.
func TestDeferredRerun(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.generation = 3
	m.activeJob = &job{id: "j", gen: 3, cancel: func() {}}

	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendRerun {
		t.Fatal("r during a job must defer a rerun")
	}

	u2, cmd2 := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModelP(t, u2)
	if nm2.generation != 4 {
		t.Errorf("generation = %d, want 4 after deferred rerun", nm2.generation)
	}
	if cmd2 == nil {
		t.Error("deferred rerun must issue a reschedule cmd")
	}
}

// A tool hotkey while a job runs defers the tool launch (last write wins).
func TestDeferredTool(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.generation = 1
	canceled := false
	m.activeJob = &job{id: "j", gen: 1, cancel: func() { canceled = true }}

	u, _ := m.Update(keyMsg("p")) // ping hotkey
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendTool {
		t.Fatal("a tool hotkey during a job must defer the launch")
	}
	if nm.pending.tool.Key != "p" {
		t.Errorf("deferred tool = %q, want ping (p)", nm.pending.tool.Key)
	}
	if !canceled {
		t.Error("the running job must be canceled before the new tool")
	}
}

// Output lines route to the right buffer; stale-generation messages are dropped.
func TestToolOutputRouting(t *testing.T) {
	m := newModel(nil)
	m.generation = 1
	m.activeJob = &job{id: "j", gen: 1, ch: make(chan tea.Msg, 1)}

	u, cmd := m.Update(ToolOutputMsg{JobID: "j", Generation: 1, Stream: StreamStdout, Line: "hello"})
	nm := asModel(t, u)
	if len(nm.jobOut) != 1 || nm.jobOut[0] != "hello" {
		t.Errorf("jobOut = %v, want [hello]", nm.jobOut)
	}
	if cmd == nil {
		t.Error("an accepted output line must reissue waitForMsg")
	}

	u, _ = nm.Update(ToolOutputMsg{JobID: "j", Generation: 1, Stream: StreamStderr, Line: "oops"})
	nm = asModel(t, u)
	if len(nm.jobErr) != 1 || nm.jobErr[0] != "oops" {
		t.Errorf("jobErr = %v, want [oops]", nm.jobErr)
	}

	// Stale generation → ignored.
	u, cmd = nm.Update(ToolOutputMsg{JobID: "j", Generation: 99, Stream: StreamStdout, Line: "nope"})
	nm = asModel(t, u)
	if len(nm.jobOut) != 1 {
		t.Errorf("stale output must be dropped, jobOut = %v", nm.jobOut)
	}
	if cmd != nil {
		t.Error("stale output must issue no cmd")
	}
}

// A terminal event for a stale job (wrong id/gen) is ignored.
func TestStaleToolDoneDropped(t *testing.T) {
	m := newModel(nil)
	m.generation = 2
	m.activeJob = &job{id: "j", gen: 2, cancel: func() {}}
	u, cmd := m.Update(ToolDoneMsg{JobID: "other", Generation: 2, Status: JobDone})
	nm := asModel(t, u)
	if nm.activeJob == nil {
		t.Error("a mismatched-id terminal event must not clear the active job")
	}
	if cmd != nil {
		t.Error("stale terminal event must issue no cmd")
	}
}

func TestWindowSize(t *testing.T) {
	m := newModel(nil)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	nm := asModel(t, u)
	if nm.width != 120 || nm.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", nm.width, nm.height)
	}
}

// launchTool on a missing binary fails gracefully with an install hint and no cmd.
func TestLaunchToolUnavailable(t *testing.T) {
	m := newModel(nil)
	tool := Tool{
		Key: "z", Name: "nope", Bin: "network-doctor-no-such-binary-xyz",
		Build: func(*Target) ([]string, []string, string) { return nil, nil, "nope" },
	}
	cmd := (&m).launchTool(tool)
	if cmd != nil {
		t.Error("a missing binary must not spawn anything")
	}
	if m.jobStatus != JobFailed {
		t.Errorf("status = %v, want JobFailed", m.jobStatus)
	}
	if len(m.jobErr) == 0 || !strings.Contains(m.jobErr[0], "not found") {
		t.Errorf("jobErr = %v, want a 'not found' hint", m.jobErr)
	}
}

// ---- render smoke tests (must not panic; show key labels) ----

func TestViewRenders(t *testing.T) {
	m := newModel(nil)
	out := m.View()
	for _, want := range []string{"Network Doctor", "Diagnosis"} {
		if !strings.Contains(out, want) {
			t.Errorf("View missing %q", want)
		}
	}

	tb := newModel(nil)
	tb.toolbox = true
	if !strings.Contains(tb.View(), "Toolbox mode") {
		t.Error("deferred toolbox view must explain itself")
	}

	job := newModel(mustTarget(t, "github.com"))
	job.jobStatus, job.jobName, job.jobDisplay = JobDone, "ping", "ping github.com"
	job.jobOut = []string{"64 bytes from ..."}
	if !strings.Contains(job.View(), "$ ping github.com") {
		t.Error("job view must show the command line")
	}

	net := newModel(nil)
	net.results[pIface] = ProbeResult{Status: StatusPass, Network: "HomeWiFi"}
	if !strings.Contains(net.View(), "Wi-Fi: HomeWiFi") {
		t.Error("view must show the connected network")
	}
}

func TestExportKey(t *testing.T) {
	t.Chdir(t.TempDir())
	m := newModel(nil)
	u, _ := m.Update(keyMsg("e"))
	nm := asModel(t, u)
	if !strings.HasPrefix(nm.exportMsg, "exported") {
		t.Errorf("exportMsg = %q, want an 'exported …' confirmation", nm.exportMsg)
	}
}
