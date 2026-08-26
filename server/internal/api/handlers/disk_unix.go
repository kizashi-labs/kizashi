//go:build !windows

package handlers

import "syscall"

// checkDisk returns disk free space on Unix/Linux.
func checkDisk() DiskInfo {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		msg := err.Error()
		return DiskInfo{Name: "disk", Status: "unknown", Message: msg}
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)

	diskStatus := "up"
	if freeGB < 1.0 {
		diskStatus = "warning"
	}

	return DiskInfo{Name: "disk", Status: diskStatus, FreeGB: &freeGB}
}
