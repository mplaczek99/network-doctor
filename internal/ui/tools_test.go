package ui

import (
	"slices"
	"strings"
	"testing"
	"time"
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

	got := toolsFor(tgt, "linux")
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
	generic := toolsFor(nil, "linux")
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
	facts := extractFacts("c", "linux", stdout)
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
	facts := extractFacts("p", "linux", stdout)
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
	facts := extractFacts("d", "linux", stdout)
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

// psArgs targets PowerShell: single-quote literals, embedded ' doubled, and
// %{…} quoted so curl's format string stays inert.
func TestPsArgsQuotes(t *testing.T) {
	got := psArgs([]string{"-w", `%{http_code}\n`, "it's", "https://x"})
	want := `-w '%{http_code}\n' 'it''s' https://x`
	if got != want {
		t.Errorf("psArgs = %q, want %q", got, want)
	}
}

func toolByKey(t *testing.T, tools []Tool, key string) Tool {
	t.Helper()
	for _, tl := range tools {
		if tl.Key == key {
			return tl
		}
	}
	t.Fatalf("tool %q not offered", key)
	return Tool{}
}

// The Windows table: OS built-ins (route print, netstat -ano, ping -n,
// nslookup, curl.exe, tracert, pathping), NUL instead of /dev/null, a
// PowerShell-target display without the LC_ALL prefix, and pathping's own
// 90 s timeout.
func TestToolsForWindows(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tools := toolsFor(tgt, "windows")

	wantBins := map[string]string{
		"i": "route", "s": "netstat", "p": "ping", "d": "nslookup",
		"c": "curl.exe", "t": "tracert", "m": "pathping",
	}
	if len(tools) != len(wantBins) {
		t.Fatalf("windows table has %d tools, want %d", len(tools), len(wantBins))
	}
	for key, bin := range wantBins {
		if got := toolByKey(t, tools, key).Bin; got != bin {
			t.Errorf("windows %q Bin = %q, want %q", key, got, bin)
		}
	}

	if args, _, _ := toolByKey(t, tools, "p").Build(tgt); !slices.Equal(args, []string{"-n", "4", "-w", "2000", "github.com"}) {
		t.Errorf("windows ping argv = %q", args)
	}

	curl := toolByKey(t, tools, "c")
	args, env, display := curl.Build(tgt)
	if !slices.Contains(args, "NUL") || slices.Contains(args, "/dev/null") {
		t.Errorf("windows curl must write to NUL, argv = %q", args)
	}
	if !strings.HasPrefix(display, "curl.exe ") || strings.Contains(display, "LC_ALL") {
		t.Errorf("windows curl display = %q, want curl.exe prefix without LC_ALL", display)
	}
	if !strings.Contains(display, `'%{http_code}`) {
		t.Errorf("windows curl display must PowerShell-quote the -w format: %q", display)
	}
	if len(env) == 0 || env[len(env)-1] != "LC_ALL=C" {
		t.Errorf("curl env must still set LC_ALL=C (harmless on Windows), got tail of %d entries", len(env))
	}

	pp := toolByKey(t, tools, "m")
	if pp.Timeout != 90*time.Second {
		t.Errorf("pathping Timeout = %v, want 90s", pp.Timeout)
	}
	if args, _, _ := pp.Build(tgt); !slices.Equal(args, []string{"-h", "20", "-q", "5", "-p", "100", "-w", "500", "github.com"}) {
		t.Errorf("pathping argv = %q", args)
	}

	if args, _, _ := toolByKey(t, tools, "t").Build(tgt); !slices.Equal(args, []string{"-w", "2000", "-h", "20", "github.com"}) {
		t.Errorf("tracert argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "i").Build(tgt); !slices.Equal(args, []string{"print", "-4"}) {
		t.Errorf("route print argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt); !slices.Equal(args, []string{"-ano"}) {
		t.Errorf("netstat argv = %q", args)
	}
}

// The macOS table: netstat for routes/sockets, ping without -W (BSD ping's -W
// is milliseconds), dig/curl/traceroute/mtr as on Linux.
func TestToolsForDarwin(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tools := toolsFor(tgt, "darwin")

	if args, _, _ := toolByKey(t, tools, "i").Build(tgt); !slices.Equal(args, []string{"-rn"}) {
		t.Errorf("darwin routes argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt); !slices.Equal(args, []string{"-an", "-p", "tcp"}) {
		t.Errorf("darwin sockets argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "p").Build(tgt); !slices.Equal(args, []string{"-c", "4", "github.com"}) {
		t.Errorf("darwin ping argv = %q (BSD -W must be omitted)", args)
	}
	if bin := toolByKey(t, tools, "d").Bin; bin != "dig" {
		t.Errorf("darwin d = %q, want dig", bin)
	}
	if bin := toolByKey(t, tools, "m").Bin; bin != "mtr" {
		t.Errorf("darwin m = %q, want mtr", bin)
	}
	if bin := toolByKey(t, tools, "c").Bin; bin != "curl" {
		t.Errorf("darwin c = %q, want curl", bin)
	}
	if pt := toolByKey(t, tools, "m").Timeout; pt != 0 {
		t.Errorf("darwin mtr Timeout = %v, want 0 (default)", pt)
	}
}

// Every table keeps the same hotkey set so muscle memory transfers across OSes.
func TestToolTablesSameHotkeys(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	want := []string{"i", "s", "p", "d", "c", "t", "m"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		var keys []string
		for _, tl := range toolsFor(tgt, goos) {
			keys = append(keys, tl.Key)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("%s hotkeys = %v, want %v", goos, keys, want)
		}
	}
}

// Windows ping facts: "(X% loss)" and "Average = Xms" (English-only, documented).
func TestExtractPingWindows(t *testing.T) {
	stdout := []string{
		"Pinging github.com [140.82.112.3] with 32 bytes of data:",
		"Reply from 140.82.112.3: bytes=32 time=16ms TTL=52",
		"    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),",
		"    Minimum = 15ms, Maximum = 18ms, Average = 16ms",
	}
	facts := extractFacts("p", "windows", stdout)
	if v, ok := factVal(facts, "packet_loss"); !ok || v != "0% loss" {
		t.Errorf("packet_loss = %q (%v), want '0%% loss'", v, ok)
	}
	if v, ok := factVal(facts, "rtt_avg"); !ok || v != "16ms" {
		t.Errorf("rtt_avg = %q (%v), want 16ms", v, ok)
	}
}

// nslookup facts are locale-independent: skip the resolver stanza, then keep
// every IPv4 token — covers Address:, Addresses:, and indented continuations.
func TestExtractNslookup(t *testing.T) {
	stdout := []string{
		"Server:  router.local",
		"Address:  192.168.1.1",
		"",
		"Non-authoritative answer:",
		"Name:    github.com",
		"Addresses:  140.82.112.3",
		"          140.82.113.4",
	}
	facts := extractFacts("d", "windows", stdout)
	if v, ok := factVal(facts, "A_records"); !ok || v != "140.82.112.3, 140.82.113.4" {
		t.Errorf("A_records = %q (%v), want both answer IPs and not the resolver's", v, ok)
	}

	// Resolver-only output (lookup failed before any answer) yields nothing.
	if got := extractFacts("d", "windows", []string{"Server: r", "Address: 192.168.1.1"}); got != nil {
		t.Errorf("resolver-only output → %v, want nil", got)
	}
}
