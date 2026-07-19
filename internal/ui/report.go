package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// exportReport saves the report next to the user (save=true) or copies it to
// the clipboard via OSC 52, and returns the one-line notice for the help bar
// plus whether the export succeeded.
func exportReport(rep string, save bool) (notice string, ok bool) {
	if save {
		// cwd first (where the user is looking), $HOME as fallback — the cwd
		// may be read-only when launched from an installed location.
		name := fmt.Sprintf("network-doctor-%s.txt", time.Now().Format("20060102-150405"))
		path, err := filepath.Abs(name)
		if err == nil {
			err = reportWriteFile(path, []byte(rep), 0o600)
		}
		if err != nil {
			home, homeErr := reportUserHomeDir()
			if homeErr != nil {
				return "save failed: " + homeErr.Error(), false
			}
			path, err = filepath.Abs(filepath.Join(home, name))
			if err == nil {
				err = reportWriteFile(path, []byte(rep), 0o600)
			}
		}
		if err != nil {
			return "save failed: " + err.Error(), false
		}
		return "report saved to " + path, true
	}
	if err := copyReport(rep); err != nil {
		return "copy failed: " + err.Error(), false
	}
	return "report copied to clipboard", true
}

var (
	reportWriteFile   = os.WriteFile
	reportUserHomeDir = os.UserHomeDir
	clipboardWriteAll = clipboard.WriteAll
)

func copyReport(rep string) error {
	if clipboardWriteAll(rep) == nil {
		return nil
	}
	// stderr, because Bubble Tea owns stdout: both reach the tty, but only one
	// of them is fighting the renderer for it mid-frame.
	_, err := os.Stderr.WriteString(osc52Sequence(rep))
	return err
}

// osc52Sequence encodes rep as an OSC 52 clipboard escape, the "please copy
// this" request terminals honor even over SSH. Inside tmux the sequence must
// ride tmux's DCS passthrough envelope, or tmux quietly eats it.
func osc52Sequence(rep string) string {
	seq := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(rep)) + "\a"
	if os.Getenv("TMUX") != "" {
		return "\x1bPtmux;\x1b" + seq + "\x1b\\"
	}
	return seq
}

// report renders the finished run as plain text safe to paste into a ticket
// or chat: no ANSI styling, and every field that can carry external bytes
// (probe details, attempt errors, SSIDs, tool output) goes through
// textsafe.Clean.
func (m model) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network-doctor report — %s\n", time.Now().UTC().Format(time.RFC3339))
	if m.target != nil {
		fmt.Fprintf(&b, "target: %s (%s)\n", m.targetHP(), m.target.Proto)
	} else {
		b.WriteString("target: none — general connection check\n")
	}
	b.WriteString("verdict: " + m.verdictLine() + "\n\nchecks:\n")
	for _, p := range m.probes {
		r := m.results[p.ID]
		fmt.Fprintf(&b, "  [%s] %s — %s\n", r.Status, p.Name, textsafe.Clean(r.Detail))
		if (r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusWarn) && r.Fix != "" {
			b.WriteString("        fix: " + textsafe.Clean(r.Fix) + "\n")
		}
		if r.Source != nil {
			b.WriteString("        src: " + r.Source.String() + " " + textsafe.Clean(r.Iface) + "\n")
		}
		if r.Network != "" {
			b.WriteString("        wifi: " + textsafe.Clean(r.Network) + "\n")
		}
		for _, a := range r.Attempts {
			st := "ok"
			if a.Err != nil {
				st = textsafe.Clean(a.Err.Error())
			}
			fmt.Fprintf(&b, "        attempt: %s %dms %s\n", a.IP, a.Dur.Milliseconds(), st)
		}
	}
	if len(m.jobLines) > 0 {
		const reportTailLines = 15
		lines := m.jobLines
		if len(lines) > reportTailLines {
			lines = lines[len(lines)-reportTailLines:]
		}
		fmt.Fprintf(&b, "\ntool output ($ %s):\n", textsafe.Clean(m.jobDisplay))
		for _, line := range lines {
			b.WriteString("  " + textsafe.Clean(line) + "\n")
		}
	}
	return b.String()
}

// verdictLine is the banner verdict without styling: PASS/WARN/FAIL plus the
// diagnosis summary.
func (m model) verdictLine() string {
	order, firstFail, anyWarn := m.resultState()
	summary := diagnostic.Diagnose(m.target, order, m.results)
	switch {
	case firstFail != nil:
		return "FAIL — " + summary
	case anyWarn:
		return "WARN — " + summary
	}
	return "PASS — " + summary
}
