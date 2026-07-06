package ui

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mplaczek99/network-doctor/internal/diagnostic"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key     string        // single-key hotkey / stable id
	Name    string        // display label
	Bin     string        // binary to resolve via LookPath
	Timeout time.Duration // per-tool job timeout; 0 = default toolTimeout
	Confirm bool          // show the exact command and wait for a keypress before running
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	Build func(t *diagnostic.Target) (args, env []string, display string)
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
func toolsFor(t *diagnostic.Target, goos string) []Tool {
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

	// The "c" slot is the application-layer check, matched to the target's
	// protocol: curl only fits HTTP(S), so SSH and SMTP targets get a bounded
	// handshake probe instead.
	switch t.Proto {
	case diagnostic.ProtoSSH:
		tools = append(tools, sshTool(quote, host, t.Port, goos))
	case diagnostic.ProtoSMTP:
		tools = append(tools, smtpTool(quote, host, t.Port))
	default:
		tools = append(tools, curlTool(host, goos))
	}

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

	// nmap is the one advanced tool: it actively scans the target, so it's
	// gated behind a shown-command confirmation (Confirm) rather than launching
	// on the hotkey like everything else.
	tools = append(tools, nmapTool(host, goos))
	return tools
}

// nmapTool builds the nmap adapter: an explicitly-confirmed port scan with
// conservative defaults, because a scan can trip the target's intrusion
// detection. A plain TCP connect scan (-sT — no raw sockets or root, so the
// shown command is exactly what runs at any privilege), polite timing (-T2) to
// keep the probe rate low, host discovery skipped (-Pn, the target is already
// known reachable), and a hard --host-timeout so the run always ends and yields
// partial results before the job timeout kills it. An explicit target port
// scans only that port; otherwise the 100 most common ports. Deliberately no
// -sV/-O/-A: version and OS detection are louder, slower, and not needed to
// answer "is the port open?".
func nmapTool(host, goos string) Tool {
	quote := shellArgs
	if goos == "windows" {
		quote = psArgs
	}
	return Tool{
		Key: "n", Name: "nmap", Bin: "nmap", Confirm: true, Timeout: 120 * time.Second,
		Build: func(t *diagnostic.Target) ([]string, []string, string) {
			args := []string{"-sT", "-T2", "-Pn", "--host-timeout", "90s"}
			if t.PortExplicit {
				args = append(args, "-p", strconv.Itoa(t.Port))
			} else {
				args = append(args, "--top-ports", "100")
			}
			args = append(args, host)
			return args, nil, "nmap " + quote(args)
		},
	}
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
		Build: func(t *diagnostic.Target) ([]string, []string, string) {
			scheme := "https"
			if t.Proto == diagnostic.ProtoHTTP {
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

// sshTool builds a bounded SSH handshake check for the "c" slot: -v prints the
// server's protocol banner and key exchange on stderr, BatchMode=yes forbids
// prompts so the run never blocks on input, and a throwaway known-hosts file
// avoids both host-key prompts and writes to the user's known_hosts. If an
// agent key does authenticate, the remote command is a bare "exit".
// ConnectTimeout plus the job timeout bound the run.
func sshTool(quote func([]string) string, host string, port int, goos string) Tool {
	knownHosts := "/dev/null"
	if goos == "windows" {
		knownHosts = "NUL"
	}
	return staticTool(quote, "c", "ssh", "ssh",
		"-v",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-p", strconv.Itoa(port),
		host, "exit")
}

// smtpTool builds a bounded SMTP STARTTLS check for the "c" slot (ProtoSMTP is
// only inferred for ports 25 and 587, both STARTTLS). In the TUI the process
// gets an empty stdin, so s_client exits right after the handshake instead of
// waiting for commands; the job timeout bounds the rest.
func smtpTool(quote func([]string) string, host string, port int) Tool {
	return staticTool(quote, "c", "openssl s_client", "openssl",
		"s_client", "-starttls", "smtp", "-connect", host+":"+strconv.Itoa(port))
}

// staticTool builds a target-independent Tool whose argv is fixed at construction
// (a host, if any, is already baked into args). slices.Clone gives each Build call
// independent slices, matching the per-call allocation of the literals it replaces.
func staticTool(quote func([]string) string, key, name, bin string, args ...string) Tool {
	return Tool{Key: key, Name: name, Bin: bin, Build: func(*diagnostic.Target) ([]string, []string, string) {
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
		// The "c" hotkey is ssh/s_client on SSH/SMTP targets; require the
		// curl -w shape (3-digit code, IP in field 3) so their output — e.g.
		// an SMTP "220 host ESMTP ..." greeting — never mis-parses as facts.
		for i := len(stdout) - 1; i >= 0; i-- {
			f := strings.Fields(stdout[i])
			if len(f) == 4 && len(f[0]) == 3 &&
				strings.TrimLeft(f[0], "0123456789") == "" && net.ParseIP(f[2]) != nil {
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
	case "m":
		if goos == "windows" {
			return routeFacts(pathpingHops(stdout))
		}
		return routeFacts(mtrHops(stdout))
	case "n":
		return nmapFacts(stdout)
	}
	return facts
}

// nmapPortRE matches an open-port row ("443/tcp  open  https"). The mandatory
// whitespace after "open" excludes the "open|filtered" state, which is a maybe,
// not an open port.
var nmapPortRE = regexp.MustCompile(`^(\d+)/(?:tcp|udp)\s+open\s+(\S+)`)

// nmapFacts summarizes an nmap scan as the list of open ports ("22/ssh,
// 443/https"), the one signal worth surfacing; the raw output stays
// authoritative for the rest.
func nmapFacts(stdout []string) []Fact {
	var open []string
	for _, ln := range stdout {
		if m := nmapPortRE.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			open = append(open, m[1]+"/"+m[2])
		}
	}
	if len(open) == 0 {
		return nil
	}
	return []Fact{{"open_ports", strings.Join(open, ", ")}}
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

// routeHop is one parsed hop from mtr --report or pathping statistics.
type routeHop struct {
	n    int
	host string
	loss float64 // percent
	avg  float64 // avg (mtr) or per-hop (pathping) RTT in ms; -1 = no data
}

// ponytail: fixed thresholds — 10% loss is suspicious, a 50ms avg-RTT jump is
// a spike; make them per-tool knobs only if real routes prove them wrong.
const routeLossMin, routeSpikeMin = 10.0, 50.0

// mtrHopRE matches report rows like
// "  2.|-- 10.0.0.1  20.0%  5  8.4  9.1  8.0  10.2  0.9"
// (hop, host, Loss%, Snt, Last, Avg, ...). The % is optional: some builds
// print unresponsive hops as "100.0" without it.
var mtrHopRE = regexp.MustCompile(`^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%?\s+\d+\s+[\d.]+\s+([\d.]+)`)

func mtrHops(stdout []string) []routeHop {
	var hops []routeHop
	for _, ln := range stdout {
		m := mtrHopRE.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		loss, _ := strconv.ParseFloat(m[3], 64)
		avg, _ := strconv.ParseFloat(m[4], 64)
		if loss >= 100 {
			avg = -1 // all probes lost; the 0.0 timings are meaningless
		}
		hops = append(hops, routeHop{n, m[2], loss, avg})
	}
	return hops
}

// pathpingHopRE matches statistics rows like
// "  2   8ms   10/ 100 = 10%   5/ 100 =  5%  10.0.0.1"
// (hop, RTT or ---, source-to-here loss, this-node loss, address). The hop's
// own loss is the second percentage; the source-to-here column accumulates
// upstream loss. Link-loss "|" rows and the hop-0 header row don't match.
// English-locale output only, same documented limitation as Windows ping.
var pathpingHopRE = regexp.MustCompile(`^\s*(\d+)\s+(?:(\d+)ms|---)\s+\d+/\s*\d+\s*=\s*(\d+)%\s+\d+/\s*\d+\s*=\s*(\d+)%\s+(\S.*)$`)

func pathpingHops(stdout []string) []routeHop {
	var hops []routeHop
	for _, ln := range stdout {
		m := pathpingHopRE.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		loss, _ := strconv.ParseFloat(m[4], 64)
		avg := -1.0
		if m[2] != "" {
			avg, _ = strconv.ParseFloat(m[2], 64)
		}
		hops = append(hops, routeHop{n, strings.TrimSpace(m[5]), loss, avg})
	}
	return hops
}

// routeFacts summarizes route quality from parsed hops: destination loss, the
// lossiest hop, the biggest latency jump, and the first suspicious hop. Loss
// at an intermediate hop that clears by the destination is ICMP
// deprioritization, not path loss, so suspicion needs loss that persists to
// the destination, a trailing run of silent hops, or a latency spike.
func routeFacts(hops []routeHop) []Fact {
	if len(hops) == 0 {
		return nil
	}
	dest := hops[len(hops)-1]
	facts := []Fact{{"dest_loss", routePct(dest.loss)}}

	// Lossiest hop, ignoring silent (100%) hops: routers that answer no
	// probes at all are noise unless the path dies there, which suspect_hop
	// reports.
	worst := routeHop{loss: -1}
	for _, h := range hops {
		if h.loss < 100 && h.loss > worst.loss {
			worst = h
		}
	}
	if worst.loss > 0 {
		facts = append(facts, Fact{"worst_hop",
			fmt.Sprintf("%s loss at hop %d (%s)", routePct(worst.loss), worst.n, worst.host)})
	}

	var spikeHop routeHop
	spike, prev := 0.0, -1.0
	for _, h := range hops {
		if h.avg < 0 {
			continue
		}
		if prev >= 0 && h.avg-prev > spike {
			spike, spikeHop = h.avg-prev, h
		}
		prev = h.avg
	}
	if spike >= routeSpikeMin {
		facts = append(facts, Fact{"latency_spike",
			fmt.Sprintf("+%.0fms at hop %d (%s)", spike, spikeHop.n, spikeHop.host)})
	}

	if h, why := routeSuspect(hops, spike, spikeHop); why != "" {
		facts = append(facts, Fact{"suspect_hop",
			fmt.Sprintf("hop %d (%s): %s", h.n, h.host, why)})
	}
	return facts
}

// routeSuspect picks the first hop where trouble starts, or a zero hop and ""
// when the route looks healthy.
func routeSuspect(hops []routeHop, spike float64, spikeHop routeHop) (routeHop, string) {
	dest := hops[len(hops)-1]
	if dest.loss >= 100 {
		i := len(hops) - 1
		for i > 0 && hops[i-1].loss >= 100 {
			i--
		}
		return hops[i], "no replies from here to destination"
	}
	if dest.loss >= routeLossMin {
		// ponytail: naive origin pick — first hop with real loss; a
		// rate-limited hop upstream of the true origin can win the blame.
		for _, h := range hops {
			if h.loss >= routeLossMin && h.loss < 100 {
				return h, fmt.Sprintf("%s loss persisting to destination", routePct(h.loss))
			}
		}
	}
	if spike >= routeSpikeMin {
		return spikeHop, fmt.Sprintf("latency jumps +%.0fms", spike)
	}
	return routeHop{}, ""
}

// routePct renders a loss percentage without trailing zeros ("20%", "0.5%").
func routePct(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64) + "%"
}
