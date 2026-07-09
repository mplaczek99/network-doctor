//go:build unix

package ui

import (
	"os/exec"
	"syscall"
)

// setProcGroup makes cmd a process-group leader so killGroup can reach
// descendants (e.g. mtr-packet).
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup SIGKILLs the whole process group so descendants die too.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		return syscall.Kill(-pgid, syscall.SIGKILL)
	}
	// Getpgid failed — the leader is likely already dead/reaped. Plain Kill as
	// a consolation prize; any surviving grandchildren get adopted by init.
	return cmd.Process.Kill()
}
