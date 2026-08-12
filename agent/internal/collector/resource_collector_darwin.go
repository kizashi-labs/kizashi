package collector

import "syscall"

// readCPUStat is not implemented on Darwin without cgo/sysctl.
// Returns (0, 0) so CPU% will always be reported as 0 on macOS.
func readCPUStat() (idle, total uint64) {
	return 0, 0
}

// readDiskFreeGB returns free disk space in GB for the root filesystem on macOS.
func readDiskFreeGB() float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	return float64(freeBytes) / (1024 * 1024 * 1024)
}
