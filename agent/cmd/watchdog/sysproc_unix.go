//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group (Unix).
// This prevents SIGINT from the terminal propagating automatically to the agent.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// gracefulStop sends SIGTERM to the child process group.
func gracefulStop(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// Negative PID targets the whole process group
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
