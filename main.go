package main

import (
	"flag"
	"fmt"
	"io"
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
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "network-doctor", version)
		return 0
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

	p := tea.NewProgram(ui.New(t, *toolbox), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(stderr, "network-doctor:", err)
		return 1
	}
	return ui.ExitCode(final)
}
