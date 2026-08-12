//go:build linux

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processListImpl reads /proc to enumerate running processes on Linux.
func processListImpl() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var procs []ProcessInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
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
