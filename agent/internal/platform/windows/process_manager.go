//go:build windows

package windows

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// WindowsProcessManager implements collector.ProcessManager for Windows.
type WindowsProcessManager struct{}

// NewWindowsProcessManager returns a new WindowsProcessManager.
func NewWindowsProcessManager() *WindowsProcessManager {
	return &WindowsProcessManager{}
}

// Kill terminates the process with the given PID using TerminateProcess.
func (m *WindowsProcessManager) Kill(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(pid=%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("TerminateProcess(pid=%d): %w", pid, err)
	}
	return nil
}
