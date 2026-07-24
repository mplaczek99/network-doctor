package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
	"github.com/heymaikol/network-doctor/internal/ui"
)

// version is injected by GoReleaser via -X main.version={{.Version}}.
var version = "dev"

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		version = versionString(version, info.Main.Version)
	}
}

// versionString picks what -version reports: the GoReleaser-injected value
// when there is one, else the module version stamped into the binary — so a
// plain `go install ...@vX.Y.Z` build doesn't introduce itself as "dev".
func versionString(injected, module string) string {
	if injected == "dev" && module != "" && module != "(devel)" {
		return module
	}
	return injected
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netdoc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// Suppress the automatic usage dump: an explicit -help prints the full
	// usage on stdout and exits 0, a parse error gets only a one-line hint.
	fs.Usage = func() {}
	toolbox := fs.Bool("toolbox", false, "start in toolbox mode")
	jsonOut := fs.Bool("json", false, "run the checks headless and print a JSON report")
	showVersion := fs.Bool("version", false, "print version and exit")
	timeout := fs.Duration("timeout", diagnostic.ProbeTimeout, "per-check probe timeout")

	// The stdlib flag package stops parsing at the first non-flag argument;
	// peel positionals off and re-parse the remainder so flags are accepted
	// both before and after the target.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				printUsage(stdout, fs)
				return 0
			}
			fmt.Fprintln(stderr, "run 'netdoc --help' for usage")
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(positional) > 1 {
		fmt.Fprintf(stderr, "netdoc: unexpected arguments: %v\n", positional[1:])
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "netdoc", version)
		return 0
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "netdoc: -timeout must be positive")
		return 2
	}
	diagnostic.ProbeTimeout = *timeout
	if *jsonOut && *toolbox {
		fmt.Fprintln(stderr, "netdoc: -json and -toolbox cannot be combined")
		return 2
	}

	var t *diagnostic.Target
	if len(positional) == 1 {
		parsed, err := diagnostic.ParseTarget(positional[0])
		if err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 2 // bad args / validation reject
		}
		t = parsed
	}

	if *jsonOut {
		return runJSON(t, stdout, stderr)
	}

	p := tea.NewProgram(ui.New(t, *toolbox), tea.WithAltScreen(), tea.WithMouseCellMotion())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", err)
		return 1
	}
	return ui.ExitCode(final)
}

// printUsage writes the full help text: usage line, the target grammar
// ParseTarget accepts, and the flags.
func printUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: netdoc [flags] [target]

Diagnoses network connectivity layer by layer. With no target it runs the
generic checks; with a target it also probes that endpoint. Flags may be
given before or after the target.

Target forms:
`+diagnostic.TargetForms+"\n\nFlags:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// The report is the stable machine-readable contract: field names and the
// status vocabulary (PASS/WARN/FAIL/SKIP/N/A) must not change once released.
type report struct {
	Version string        `json:"version"`
	Target  *reportTarget `json:"target"` // null in generic (no-target) mode
	Checks  []reportCheck `json:"checks"`
	Summary string        `json:"summary"`
	OK      bool          `json:"ok"`
}

type reportTarget struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type reportCheck struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Detail     string          `json:"detail"`
	Fix        string          `json:"fix,omitempty"`
	Addrs      []string        `json:"addrs,omitempty"`
	SelectedIP string          `json:"selected_ip,omitempty"`
	Source     string          `json:"source,omitempty"`
	Iface      string          `json:"iface,omitempty"`
	Network    string          `json:"network,omitempty"`
	Attempts   []reportAttempt `json:"attempts,omitempty"`
}

type reportAttempt struct {
	IP  string `json:"ip"`
	Ms  int64  `json:"ms"`
	Err string `json:"error,omitempty"`
}

// runJSON runs the probe DAG headless and prints the JSON report. Exit code
// mirrors the TUI contract: 1 if any check failed, else 0.
func runJSON(t *diagnostic.Target, stdout, stderr io.Writer) int {
	probes := diagnostic.BuildProbes(t)
	results := diagnostic.RunAll(context.Background(), probes)
	rep := buildReport(t, probes, results)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(stderr, "netdoc:", err)
		return 1
	}
	if rep.OK {
		return 0
	}
	return 1
}

// buildReport flattens probe results into the stable JSON shape, preserving
// probe order. OK means "no check failed" — Warn, Skip, and N/A don't count
// against it, same as everywhere else in the app.
func buildReport(t *diagnostic.Target, probes []diagnostic.Probe, results map[diagnostic.ProbeID]diagnostic.ProbeResult) report {
	rep := report{Version: version, OK: true}
	if t != nil {
		rep.Target = &reportTarget{Host: t.Host, Port: t.Port, Protocol: t.Proto.String()}
	}
	order := make([]diagnostic.ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
		r := results[p.ID]
		rep.OK = rep.OK && r.Status != diagnostic.StatusFail
		c := reportCheck{
			ID:      string(p.ID),
			Name:    p.Name,
			Status:  r.Status.String(),
			Detail:  textsafe.Clean(r.Detail),
			Fix:     r.Fix,
			Iface:   r.Iface,
			Network: textsafe.Clean(r.Network),
		}
		for _, ip := range r.Addrs {
			c.Addrs = append(c.Addrs, ip.String())
		}
		if r.SelectedIP != nil {
			c.SelectedIP = r.SelectedIP.String()
		}
		if r.Source != nil {
			c.Source = r.Source.String()
		}
		for _, a := range r.Attempts {
			ra := reportAttempt{IP: a.IP.String(), Ms: a.Dur.Milliseconds()}
			if a.Err != nil {
				ra.Err = textsafe.Clean(a.Err.Error())
			}
			c.Attempts = append(c.Attempts, ra)
		}
		rep.Checks = append(rep.Checks, c)
	}
	rep.Summary = diagnostic.Diagnose(t, order, results)
	return rep
}
