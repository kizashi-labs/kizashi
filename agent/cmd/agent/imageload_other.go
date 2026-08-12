//go:build !windows && !(linux && ebpf && solib)

package main

import "github.com/edr-platform/agent/internal/collector"

// newPlatformImageLoadCollector is a no-op on non-Windows platforms by default.
// The Linux eBPF dlopen collector is wired only under `-tags "ebpf solib"`
// (see imageload_linux_solib.go); image-load telemetry is otherwise
// Windows-only (ETW).
func newPlatformImageLoadCollector() collector.ImageLoadCollector {
	return nil
}

// newPlatformScriptCollector is a no-op on non-Windows platforms; script-content
// telemetry is currently Windows-only (PowerShell/AMSI ETW).
func newPlatformScriptCollector() collector.ScriptContentCollector {
	return nil
}
