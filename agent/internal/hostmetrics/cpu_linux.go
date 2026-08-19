//go:build linux

package hostmetrics

// readCPUStat reads the aggregate CPU counters from /proc/stat.
func readCPUStat() (idle, total uint64, ok bool) {
	return readProcStat("/proc/stat")
}

// readMemory reads the host's memory usage from /proc/meminfo.
func readMemory() (usedMB, totalMB float64, ok bool) {
	return readMemInfo("/proc/meminfo")
}
