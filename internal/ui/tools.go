package ui

import (
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key     string        // single-key hotkey / stable id
	Name    string        // display label
	Bin     string        // binary to resolve via LookPath
	Timeout time.Duration // per-tool job timeout; 0 = default toolTimeout
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	Build func(t *Target) (args, env []string, display string)
}

// Available reports whether the tool's binary is installed.
func (t Tool) Available() bool {
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// toolsFor returns the drill-down tools for the target on the given GOOS
// (production passes runtime.GOOS; tests exercise all tables from one OS).
// Same hotkeys everywhere. The target-independent tools (routes, sockets) are
// always offered; the target-dependent set only when a host is given.
func toolsFor(t *Target, goos string) []Tool {
	quote := shellArgs
	if goos == "windows" {
		quote = psArgs
	}

	var tools []Tool
	switch goos {
	case "darwin":
		tools = []Tool{
			staticTool(quote, "i", "netstat -rn", "netstat", "-rn"),
			staticTool(quote, "s", "netstat", "netstat", "-an", "-p", "tcp"),
		}
	case "windows":
		tools = []Tool{
			staticTool(quote, "i", "route print", "route", "print", "-4"),
			staticTool(quote, "s", "netstat", "netstat", "-ano"),
		}
	default: // linux (and any other unix)
		tools = []Tool{
			staticTool(quote, "i", "ip route", "ip", "route"),
			staticTool(quote, "s", "ss", "ss", "-tunp"),
		}
	}
	if t == nil {
		return tools
	}
	host := t.Host

	switch goos {
	case "darwin":
		// BSD ping's -W is milliseconds and semantics differ; omit it.
		tools = append(tools, staticTool(quote, "p", "ping", "ping", "-c", "4", host))
	case "windows":
		tools = append(tools, staticTool(quote, "p", "ping", "ping", "-n", "4", "-w", "2000", host))
	default:
		tools = append(tools, staticTool(quote, "p", "ping", "ping", "-c", "4", "-W", "2", host))
	}

	if goos == "windows" {
		tools = append(tools, staticTool(quote, "d", "nslookup", "nslookup", host))
	} else {
		tools = append(tools, staticTool(quote, "d", "dig", "dig", "+time=2", "+tries=1", host))
	}

	tools = append(tools, curlTool(host, goos))

	if goos == "windows" {
		tools = append(tools,
			staticTool(quote, "t", "tracert", "tracert", "-w", "2000", "-h", "20", host))
		// pathping's full run takes ~30–60 s; give it its own budget.
		pp := staticTool(quote, "m", "pathping", "pathping", "-h", "20", "-q", "5", "-p", "100", "-w", "500", host)
		pp.Timeout = 90 * time.Second
		tools = append(tools, pp)
	} else {
		tools = append(tools,
			staticTool(quote, "t", "traceroute", "traceroute", "-w", "2", "-q", "1", "-m", "20", host),
			// mtr report mode only — never curses inside our TUI.
			staticTool(quote, "m", "mtr", "mtr", "--report", "--report-cycles", "5", host))
	}
	return tools
}

// curlTool builds the curl adapter. On Windows the binary and the displayed
// command are both curl.exe, so the pasted line bypasses PowerShell 5.1's
// curl→Invoke-WebRequest alias; the display targets PowerShell quoting (cmd.exe
// paste is not supported). Elsewhere the display keeps the POSIX LC_ALL=C form.
func curlTool(host, goos string) Tool {
	bin, devNull := "curl", "/dev/null"
	if goos == "windows" {
		bin, devNull = "curl.exe", "NUL"
	}
	return Tool{
		Key: "c", Name: "curl", Bin: bin,
		Build: func(t *Target) ([]string, []string, string) {
			scheme := "https"
			if t.Proto == ProtoHTTP {
				scheme = "http"
			}
			url := scheme + "://" + host
			if t.PortExplicit {
				url += ":" + strconv.Itoa(t.Port)
			}
			args := []string{
				"-q", "-sS", "--head", "-o", devNull,
				"--max-redirs", "0", "--noproxy", "*",
				"--proto", "=https,http",
				"--connect-timeout", "3", "--max-time", "10",
				"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
				url,
			}
			// LC_ALL=C is set via env, not an argv token, for locale-proof -w
			// output (harmless on Windows).
			env := append(os.Environ(), "LC_ALL=C")
			if goos == "windows" {
				return args, env, "curl.exe " + psArgs(args)
			}
			return args, env, "LC_ALL=C curl " + shellArgs(args)
		},
	}
}

// staticTool builds a target-independent Tool whose argv is fixed at construction
// (a host, if any, is already baked into args). slices.Clone gives each Build call
// independent slices, matching the per-call allocation of the literals it replaces.
func staticTool(quote func([]string) string, key, name, bin string, args ...string) Tool {
	return Tool{Key: key, Name: name, Bin: bin, Build: func(*Target) ([]string, []string, string) {
		a := slices.Clone(args)
		return a, nil, bin + " " + quote(a)
	}}
}

// shellArgs renders argv for *display only* (never executed), quoting tokens with
// shell-special characters so the shown command is copy-pasteable in a POSIX shell.
func shellArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'\\$*?#&|;<>(){}[]`") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// psArgs renders argv for *display only* targeting PowerShell: single-quote
// literals with embedded quotes doubled, which also keeps curl's %{…} format
// string inert. cmd.exe paste is explicitly not supported (one shell, exact rules).
func psArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'`$*?#&|;<>(){}[],%^@") {
			out[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// Fact is display-only evidence extracted from a finished tool's output.
type Fact struct {
	Key, Value string
}

// extractFacts pulls a few stable facts from a finished tool's stdout on the
// given GOOS. Best effort across tool versions and locales (Windows ping is
// English-only, documented); the raw (sanitized) output stays authoritative.
func extractFacts(toolKey, goos string, stdout []string) []Fact {
	var facts []Fact
	switch toolKey {
	case "c": // curl -w "http_code time_total remote_ip ssl_verify_result"
		for i := len(stdout) - 1; i >= 0; i-- {
			f := strings.Fields(stdout[i])
			if len(f) == 4 {
				facts = append(facts,
					Fact{"http_code", f[0]},
					Fact{"time_total", f[1] + "s"},
					Fact{"remote_ip", f[2]},
					Fact{"ssl_verify", f[3]})
				break
			}
		}
	case "p":
		if goos == "windows" {
			return windowsPingFacts(stdout)
		}
		// Unix ping: "rtt min/avg/max/mdev = a/b/c/d ms" (macOS: "round-trip
		// min/avg/max") and "X% packet loss".
		for _, ln := range stdout {
			if i := strings.Index(ln, "packet loss"); i >= 0 {
				end := i + len("packet loss")
				if j := strings.LastIndex(ln[:i], ","); j >= 0 {
					facts = append(facts, Fact{"packet_loss", strings.TrimSpace(ln[j+1 : end])})
				}
			}
			if i := strings.Index(ln, "min/avg/max"); i >= 0 {
				if eq := strings.Index(ln, "="); eq >= 0 {
					facts = append(facts, Fact{"rtt", strings.TrimSpace(ln[eq+1:])})
				}
			}
		}
	case "d":
		if goos == "windows" {
			return nslookupFacts(stdout)
		}
		// dig: collect answer-section A records.
		var as []string
		for _, ln := range stdout {
			f := strings.Fields(ln)
			if len(f) >= 5 && f[3] == "A" {
				as = append(as, f[4])
			}
		}
		if len(as) > 0 {
			facts = append(facts, Fact{"A_records", strings.Join(as, ", ")})
		}
	}
	return facts
}

// windowsPingFacts parses "(X% loss)" and "Average = Xms" — English-locale
// output only (documented limitation).
func windowsPingFacts(stdout []string) []Fact {
	var facts []Fact
	for _, ln := range stdout {
		if i := strings.Index(ln, "% loss"); i >= 0 {
			if j := strings.LastIndex(ln[:i], "("); j >= 0 {
				facts = append(facts, Fact{"packet_loss", ln[j+1 : i+len("% loss")]})
			}
		}
		if i := strings.Index(ln, "Average = "); i >= 0 {
			facts = append(facts, Fact{"rtt_avg", strings.TrimRight(strings.TrimSpace(ln[i+len("Average = "):]), ",")})
		}
	}
	return facts
}

// nslookupFacts is locale-independent: skip the resolver's own stanza (up to
// the first blank line), then collect every token that parses as IPv4 —
// handles "Address:", "Addresses:", and indented continuation lines without
// label matching.
func nslookupFacts(stdout []string) []Fact {
	pastResolver := false
	var as []string
	for _, ln := range stdout {
		if strings.TrimSpace(ln) == "" {
			pastResolver = true
			continue
		}
		if !pastResolver {
			continue
		}
		for _, tok := range strings.Fields(ln) {
			if ip := net.ParseIP(tok); ip != nil && ip.To4() != nil {
				as = append(as, tok)
			}
		}
	}
	if len(as) == 0 {
		return nil
	}
	return []Fact{{"A_records", strings.Join(as, ", ")}}
}
