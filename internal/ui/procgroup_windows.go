//go:build windows

package ui

import "os/exec"

// setProcGroup is a no-op: the Windows tool set (ping/tracert/pathping/
// netstat/nslookup/curl) spawns no descendant trees, so killing the process
// itself suffices.
// ponytail: plain Kill; Job Objects are the upgrade path if a tree-killing
// tool ever lands in the table.
func setProcGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
