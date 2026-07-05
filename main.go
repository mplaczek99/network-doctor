package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/ui"
)

// version is injected by GoReleaser via -X main.version={{.Version}}.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("network-doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	toolbox := fs.Bool("toolbox", false, "start in toolbox mode")
	jsonOut := fs.Bool("json", false, "run the checks headless and print a JSON report")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "network-doctor", version)
		return 0
	}
	if *jsonOut && *toolbox {
		fmt.Fprintln(stderr, "network-doctor: -json and -toolbox cannot be combined")
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "network-doctor: unexpected arguments: %v\n", fs.Args()[1:])
		return 2
	}

	var t *diagnostic.Target
	if arg := fs.Arg(0); arg != "" {
		parsed, err := diagnostic.ParseTarget(arg)
		if err != nil {
			fmt.Fprintln(stderr, "network-doctor:", err)
			return 2 // bad args / validation reject
		}
		t = parsed
	}

	if *jsonOut {
		return runJSON(t, stdout, stderr)
	}

	p := tea.NewProgram(ui.New(t, *toolbox), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(stderr, "network-doctor:", err)
		return 1
	}
	return ui.ExitCode(final)
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

func runJSON(t *diagnostic.Target, stdout, stderr io.Writer) int {
	probes := diagnostic.BuildProbes(t)
	results := diagnostic.RunAll(context.Background(), probes)
	rep := buildReport(t, probes, results)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(stderr, "network-doctor:", err)
		return 1
	}
	if rep.OK {
		return 0
	}
	return 1
}

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
			Detail:  r.Detail,
			Fix:     r.Fix,
			Iface:   r.Iface,
			Network: r.Network,
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
				ra.Err = a.Err.Error()
			}
			c.Attempts = append(c.Attempts, ra)
		}
		rep.Checks = append(rep.Checks, c)
	}
	rep.Summary = diagnostic.Diagnose(t, order, results)
	if rep.Summary == "" {
		// Same wording as the TUI banner fallbacks.
		if rep.OK {
			rep.Summary = "All checks passed — no problems found."
			if t != nil {
				rep.Summary = fmt.Sprintf("All checks passed — %s looks healthy.", net.JoinHostPort(t.Host, fmt.Sprint(t.Port)))
			}
		} else {
			rep.Summary = "A check failed — see the failed check for details."
		}
	}
	return rep
}
