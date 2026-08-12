package collector

// readCPUStat is not implemented on Windows without cgo.
// Returns (0, 0) so CPU% will always be reported as 0 on Windows.
func readCPUStat() (idle, total uint64) {
	return 0, 0
}

// readDiskFreeGB is not implemented on Windows without cgo.
// Returns 0 so disk free will always be reported as 0 on Windows.
func readDiskFreeGB() float64 {
	return 0
}
