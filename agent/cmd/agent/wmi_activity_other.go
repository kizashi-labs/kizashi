//go:build !windows

package main

// newPlatformWMIActivityCollector is a no-op on non-Windows platforms; WMI is a
// Windows subsystem with no cross-platform analogue.
func newPlatformWMIActivityCollector() wmiActivityStarter {
	return nil
}
