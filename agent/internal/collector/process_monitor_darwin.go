//go:build darwin

package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processListImpl reads /proc on Darwin (macOS).
// Note: macOS does not expose /proc by default. This implementation returns an
// empty list on macOS. A production implementation would use the sysctl
// KERN_PROC_ALL call or the libproc.h API (both require cgo). The stub is
// here to satisfy the build constraint without introducing cgo or syscall
// complexity into the no-cgo agent build.
func processListImpl() ([]ProcessInfo, error) {
	// Attempt /proc first (available on some macOS builds and Docker containers).
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// /proc not available — return empty list gracefully.
		return nil, nil
	}

	var procs []ProcessInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		commPath := filepath.Join("/proc", e.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		procs = append(procs, ProcessInfo{PID: pid, Name: name})
	}
	return procs, nil
}
