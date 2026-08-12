//go:build windows

package handlers

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkDisk returns disk free space on Windows using GetDiskFreeSpaceExW.
func checkDisk() DiskInfo {
	// C:\ を対象にディスク空き容量を取得
	root, err := windows.UTF16PtrFromString(`C:\`)
	if err != nil {
		msg := err.Error()
		return DiskInfo{Name: "disk", Status: "unknown", Message: msg}
	}

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	err = windows.GetDiskFreeSpaceEx(
		root,
		(*uint64)(unsafe.Pointer(&freeBytesAvailable)),
		(*uint64)(unsafe.Pointer(&totalBytes)),
		(*uint64)(unsafe.Pointer(&totalFreeBytes)),
	)
	if err != nil {
		msg := "GetDiskFreeSpaceEx: " + err.Error()
		return DiskInfo{Name: "disk", Status: "unknown", Message: msg}
	}

	freeGB := float64(freeBytesAvailable) / (1024 * 1024 * 1024)

	status := "up"
	if freeGB < 1.0 {
		status = "warning"
	}

	return DiskInfo{Name: "disk", Status: status, FreeGB: &freeGB}
}
