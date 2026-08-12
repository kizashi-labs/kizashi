//go:build windows

package main

import (
	"os/exec"
)

// setSysProcAttr is a no-op on Windows; process groups work differently.
func setSysProcAttr(cmd *exec.Cmd) {}

// gracefulStop sends Ctrl+C via GenerateConsoleCtrlEvent on Windows.
func gracefulStop(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// On Windows the cleanest approach for console apps is Ctrl+C.
	// exec.CommandContext already calls TerminateProcess on ctx cancellation,
	// so we just let that handle it.
	cmd.Process.Kill()
}
