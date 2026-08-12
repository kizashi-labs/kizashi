//go:build windows

package tamper

import (
	"golang.org/x/sys/windows"
)

// stillActive is the exit code Windows reports for a process that has not exited
// (STILL_ACTIVE / STATUS_PENDING).
const stillActive = 259

// processAlive reports whether pid is still running.
//
// os.FindProcess cannot answer this on Windows — it succeeds for any PID — and
// Signal(0) is not implemented, so this goes through the API directly.
// PROCESS_QUERY_LIMITED_INFORMATION is deliberately the weakest right that
// answers the question: the agent may be running with fewer privileges than the
// watchdog it is checking, and asking for more would fail on exactly the hosts
// where the check matters.
//
// A process that has exited but whose handle is still open reports its real exit
// code, so the STILL_ACTIVE comparison is what separates "running" from "a zombie
// handle". A PID recycled onto another process reads as alive, which errs toward
// silence rather than a false "your watchdog is gone" alert.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
