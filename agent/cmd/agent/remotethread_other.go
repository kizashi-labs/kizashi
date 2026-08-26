//go:build !windows

package main

// newPlatformRemoteThreadCollector is a no-op on non-Windows platforms; the
// CreateRemoteThread ETW sensor is Windows-only. (Linux process injection —
// ptrace — is already covered by the eBPF LSM credential-access sensor.)
func newPlatformRemoteThreadCollector() remoteThreadStarter {
	return nil
}
