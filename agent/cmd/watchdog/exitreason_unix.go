//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// classifyExit reports the POSIX signal that killed the child, if any.
//
// On Unix this is unambiguous: WaitStatus.Signaled() separates "someone sent
// SIGKILL" from "the process exited with a non-zero status". That distinction is
// the entire basis for reporting an agent death as tampering rather than as a
// crash, so it earns the platform-specific code.
func classifyExit(err error) (sig int, signalled bool) {
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ProcessState == nil {
		return 0, false
	}
	ws, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 0, false
	}
	return int(ws.Signal()), true
}
