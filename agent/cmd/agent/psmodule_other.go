//go:build !windows

package main

// newPlatformPSModuleCollector is a no-op on non-Windows platforms; PowerShell
// Module Logging (4103) is a Windows ETW sensor with no cross-platform analogue.
func newPlatformPSModuleCollector() psModuleStarter {
	return nil
}
