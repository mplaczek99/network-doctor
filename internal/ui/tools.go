package ui

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key  string // single-key hotkey / stable id
	Name string // display label
	Bin  string // binary to resolve via LookPath
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	Build func(t *Target) (args, env []string, display string)
}

// Available reports whether the tool's binary is installed.
func (t Tool) Available() bool {
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// toolsFor returns the drill-down tools applicable to the target. The
// target-independent tools (ip route, ss) are always offered; the
// target-dependent set (ping, dig, curl, traceroute, mtr) only when a host is
// given.
func toolsFor(t *Target) []Tool {
	tools := []Tool{
		staticTool("i", "ip route", "ip", "route"),
		staticTool("s", "ss", "ss", "-tunp"),
	}
	if t == nil {
		return tools
	}
	host := t.Host
	return append(tools,
		staticTool("p", "ping", "ping", "-c", "4", "-W", "2", host),
		staticTool("d", "dig", "dig", "+time=2", "+tries=1", host),
		Tool{
			Key: "c", Name: "curl", Bin: "curl",
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
					"-q", "-sS", "--head", "-o", "/dev/null",
					"--max-redirs", "0", "--noproxy", "*",
					"--proto", "=https,http",
					"--connect-timeout", "3", "--max-time", "10",
					"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
					url,
				}
				// LC_ALL=C is set via env, not an argv token, for locale-proof -w output.
				env := append(os.Environ(), "LC_ALL=C")
				return args, env, "LC_ALL=C curl " + shellArgs(args)
			},
		},
		staticTool("t", "traceroute", "traceroute", "-w", "2", "-q", "1", "-m", "20", host),
		// mtr report mode only — never curses inside our TUI.
		staticTool("m", "mtr", "mtr", "--report", "--report-cycles", "5", host),
	)
}

// staticTool builds a target-independent Tool whose argv is fixed at construction
// (a host, if any, is already baked into args). slices.Clone gives each Build call
// independent slices, matching the per-call allocation of the literals it replaces.
func staticTool(key, name, bin string, args ...string) Tool {
	return Tool{Key: key, Name: name, Bin: bin, Build: func(*Target) ([]string, []string, string) {
		a := slices.Clone(args)
		return a, nil, bin + " " + shellArgs(a)
	}}
}

// shellArgs renders argv for *display only* (never executed), quoting tokens with
// shell-special characters so the shown command is copy-pasteable.
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

// Fact is display-only evidence extracted from a finished tool's output.
type Fact struct {
	Key, Value string
}

// extractFacts pulls a few stable facts from a finished tool's stdout. Best
// effort across tool versions; the raw (sanitized) output stays authoritative.
func extractFacts(toolKey string, stdout []string) []Fact {
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
	case "p": // ping: "rtt min/avg/max/mdev = a/b/c/d ms" and "X% packet loss"
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
	case "d": // dig: collect answer-section A records
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
