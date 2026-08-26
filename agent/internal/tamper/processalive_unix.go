//go:build !windows

package tamper

import (
	"os"
	"syscall"
)

// processAlive reports whether pid is still running.
//
// Signal 0 performs the permission and existence checks without delivering
// anything, which is the portable POSIX way to ask this question. A PID that has
// been recycled onto a different process reads as alive; that errs toward
// silence rather than toward a false "your watchdog is gone" alert.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
