//go:build !windows

package main

// newPlatformServiceInstallCollector is a no-op on non-Windows platforms;
// service-installation detection reads the Windows System log (EID 7045) and
// has no cross-platform analogue.
func newPlatformServiceInstallCollector() serviceInstallStarter {
	return nil
}
