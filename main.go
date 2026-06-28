package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/ui"
)

func main() {
	toolbox := false
	arg := ""
	for _, a := range os.Args[1:] {
		if a == "--toolbox" {
			toolbox = true
			continue
		}
		arg = a // last non-flag wins
	}

	var t *diagnostic.Target
	if arg != "" {
		parsed, err := diagnostic.ParseTarget(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "network-doctor:", err)
			os.Exit(2) // bad args / validation reject
		}
		t = parsed
	}

	p := tea.NewProgram(ui.New(t, toolbox), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "network-doctor:", err)
		os.Exit(1)
	}
	os.Exit(ui.ExitCode(final))
}
