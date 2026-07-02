package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/ui"
)

func main() {
	toolbox := flag.Bool("toolbox", false, "start in toolbox mode")
	flag.Parse()
	arg := flag.Arg(0)

	var t *diagnostic.Target
	if arg != "" {
		parsed, err := diagnostic.ParseTarget(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "network-doctor:", err)
			os.Exit(2) // bad args / validation reject
		}
		t = parsed
	}

	p := tea.NewProgram(ui.New(t, *toolbox), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "network-doctor:", err)
		os.Exit(1)
	}
	os.Exit(ui.ExitCode(final))
}
