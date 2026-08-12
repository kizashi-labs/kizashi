//go:build !windows

package main

// newPlatformNamedPipeCollector is a no-op on non-Windows platforms; named-pipe
// creation telemetry is a Windows ETW sensor (Kernel-File) with no cross-platform
// analogue.
func newPlatformNamedPipeCollector() namedPipeStarter {
	return nil
}
