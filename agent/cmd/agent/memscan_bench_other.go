//go:build !windows

package main

// benchEnableSeDebug is Windows-only; elsewhere there is no equivalent privilege
// to raise for the memory-scan bench (#511).
func benchEnableSeDebug() bool { return false }
