//go:build windows

package health

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type diskStat struct {
	Free uint64
}

func getDiskStat(path string, s *diskStat) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")
	var freeBytes, totalBytes, totalFreeBytes uint64
	ret, _, err := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return err
	}
	s.Free = freeBytes
	return nil
}
