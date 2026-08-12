//go:build !windows

package main

// newPlatformEventLogClearCollector is a no-op on non-Windows platforms;
// audit-log-clear detection reads the Windows event log (Security 1102 /
// System 104) and has no cross-platform analogue.
func newPlatformEventLogClearCollector() eventLogClearStarter {
	return nil
}
