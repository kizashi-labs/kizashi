//go:build windows

package collector

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows Toolhelp32 snapshot constants and structures.
const (
	th32csSnapProcess = 0x00000002
)

type processEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
)

// processListImpl enumerates running processes using the Toolhelp32 API on Windows.
func processListImpl() ([]ProcessInfo, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer procCloseHandle.Call(handle) //nolint:errcheck

	var entry processEntry32
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, nil // empty snapshot
	}

	var procs []ProcessInfo
	for {
		name := syscall.UTF16ToString(entry.szExeFile[:])
		procs = append(procs, ProcessInfo{
			PID:  int(entry.th32ProcessID),
			Name: name,
		})

		ret, _, _ = procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return procs, nil
}
