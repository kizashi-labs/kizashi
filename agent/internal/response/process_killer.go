package response

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcessKiller terminates processes by PID or name.
type ProcessKiller struct{}

// NewProcessKiller creates a new ProcessKiller.
func NewProcessKiller() *ProcessKiller {
	return &ProcessKiller{}
}

// KillByPID terminates a process by PID.
func (k *ProcessKiller) KillByPID(ctx context.Context, pid int) error {
	_ = ctx
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("failed to kill process %d: %w", pid, err)
	}
	return nil
}

// KillByName terminates all processes matching the given name (cross-platform).
func (k *ProcessKiller) KillByName(ctx context.Context, name string) ([]int, error) {
	pids, err := k.findPIDsByName(ctx, name)
	if err != nil {
		return nil, err
	}

	var killed []int
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := proc.Kill(); err == nil {
			killed = append(killed, pid)
		}
	}
	return killed, nil
}

// findPIDsByName finds all PIDs for processes with the given executable name.
func (k *ProcessKiller) findPIDsByName(ctx context.Context, name string) ([]int, error) {
	_ = ctx
	var pids []int

	// Try /proc (Linux)
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(comm)) == name {
				pids = append(pids, pid)
			}
		}
		return pids, nil
	}

	return pids, nil
}
