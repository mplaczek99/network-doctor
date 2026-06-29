package ui

import (
	"slices"
	"testing"
)

// TestToolsForDefinitions pins the complete, ordered tool list returned by
// toolsFor — Key, Name, Bin, argv, env, and display — for both the no-target and
// with-host sets, plus per-call slice independence. These are user-visible (hotkeys,
// labels, toolbox order, exact command shapes) and frozen, so any swap, rename, or
// argv drift from the staticTool refactor must fail here.
func TestToolsForDefinitions(t *testing.T) {
	tgt := mustTarget(t, "github.com") // https default, port not explicit

	curlArgs := []string{
		"-q", "-sS", "--head", "-o", "/dev/null",
		"--max-redirs", "0", "--noproxy", "*",
		"--proto", "=https,http",
		"--connect-timeout", "3", "--max-time", "10",
		"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
		"https://github.com",
	}

	type want struct {
		key, name, bin string
		args           []string
		display        string
		lcAllEnv       bool // true: env ends with LC_ALL=C; false: env is nil
	}
	wantHost := []want{
		{"i", "ip route", "ip", []string{"route"}, "ip route", false},
		{"s", "ss", "ss", []string{"-tunp"}, "ss -tunp", false},
		{"p", "ping", "ping", []string{"-c", "4", "-W", "2", "github.com"}, "ping -c 4 -W 2 github.com", false},
		{"d", "dig", "dig", []string{"+time=2", "+tries=1", "github.com"}, "dig +time=2 +tries=1 github.com", false},
		{"c", "curl", "curl", curlArgs, "LC_ALL=C curl " + shellArgs(curlArgs), true},
		{"t", "traceroute", "traceroute", []string{"-w", "2", "-q", "1", "-m", "20", "github.com"}, "traceroute -w 2 -q 1 -m 20 github.com", false},
		{"m", "mtr", "mtr", []string{"--report", "--report-cycles", "5", "github.com"}, "mtr --report --report-cycles 5 github.com", false},
	}

	got := toolsFor(tgt)
	if len(got) != len(wantHost) {
		t.Fatalf("toolsFor(host) returned %d tools, want %d", len(got), len(wantHost))
	}
	for i, w := range wantHost {
		tool := got[i]
		if tool.Key != w.key || tool.Name != w.name || tool.Bin != w.bin {
			t.Errorf("tool[%d] = {Key:%q Name:%q Bin:%q}, want {%q %q %q}", i, tool.Key, tool.Name, tool.Bin, w.key, w.name, w.bin)
		}
		args, env, display := tool.Build(tgt)
		if !slices.Equal(args, w.args) {
			t.Errorf("tool[%d] %s argv = %q, want %q", i, w.key, args, w.args)
		}
		if display != w.display {
			t.Errorf("tool[%d] %s display = %q, want %q", i, w.key, display, w.display)
		}
		if w.lcAllEnv {
			if len(env) == 0 || env[len(env)-1] != "LC_ALL=C" {
				t.Errorf("tool[%d] %s env must end with LC_ALL=C, got %q", i, w.key, env)
			}
		} else if env != nil {
			t.Errorf("tool[%d] %s env = %q, want nil", i, w.key, env)
		}
	}

	// No-target set: only the target-independent tools, same order.
	generic := toolsFor(nil)
	wantGeneric := []string{"i", "s"}
	if len(generic) != len(wantGeneric) {
		t.Fatalf("toolsFor(nil) returned %d tools, want %d", len(generic), len(wantGeneric))
	}
	for i, k := range wantGeneric {
		if generic[i].Key != k {
			t.Errorf("toolsFor(nil)[%d].Key = %q, want %q", i, generic[i].Key, k)
		}
	}

	// Slice independence: two Build calls must not share a backing array (Codex r1 #3).
	a1, _, _ := got[0].Build(tgt)
	a2, _, _ := got[0].Build(tgt)
	if len(a1) > 0 && &a1[0] == &a2[0] {
		t.Error("staticTool Build returned an aliased argv slice across calls")
	}
}

func factVal(facts []Fact, key string) (string, bool) {
	for _, f := range facts {
		if f.Key == key {
			return f.Value, true
		}
	}
	return "", false
}

func TestExtractCurl(t *testing.T) {
	stdout := []string{"200 0.123456 140.82.112.3 0"}
	facts := extractFacts("c", stdout)
	if v, ok := factVal(facts, "http_code"); !ok || v != "200" {
		t.Errorf("http_code = %q (%v), want 200", v, ok)
	}
	if v, ok := factVal(facts, "remote_ip"); !ok || v != "140.82.112.3" {
		t.Errorf("remote_ip = %q, want 140.82.112.3", v)
	}
	if v, ok := factVal(facts, "time_total"); !ok || v != "0.123456s" {
		t.Errorf("time_total = %q, want 0.123456s", v)
	}
}

func TestExtractPing(t *testing.T) {
	stdout := []string{
		"PING github.com (140.82.112.3) 56(84) bytes of data.",
		"4 packets transmitted, 4 received, 0% packet loss, time 3005ms",
		"rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms",
	}
	facts := extractFacts("p", stdout)
	if v, ok := factVal(facts, "packet_loss"); !ok || v != "0% packet loss" {
		t.Errorf("packet_loss = %q, want '0%% packet loss'", v)
	}
	if v, ok := factVal(facts, "rtt"); !ok || v != "1.0/2.0/3.0/0.5 ms" {
		t.Errorf("rtt = %q, want '1.0/2.0/3.0/0.5 ms'", v)
	}
}

func TestExtractDig(t *testing.T) {
	stdout := []string{
		";; ANSWER SECTION:",
		"github.com.\t60\tIN\tA\t140.82.112.3",
		"github.com.\t60\tIN\tA\t140.82.113.4",
	}
	facts := extractFacts("d", stdout)
	v, ok := factVal(facts, "A_records")
	if !ok || v != "140.82.112.3, 140.82.113.4" {
		t.Errorf("A_records = %q, want both IPs", v)
	}
}

func TestShellArgsQuotes(t *testing.T) {
	got := shellArgs([]string{"-w", `%{http_code}\n`, "https://x"})
	want := `-w '%{http_code}\n' https://x`
	if got != want {
		t.Errorf("shellArgs = %q, want %q", got, want)
	}
}
