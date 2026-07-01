//go:build !unix && !windows

package ui

import "os/exec"

// Unsupported GOOSes compile without process-group handling; a plain Kill is
// the only portable cancellation.
func setProcGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
