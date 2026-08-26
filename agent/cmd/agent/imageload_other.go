//go:build !windows && !(linux && ebpf)

package main

import "github.com/edr-platform/agent/internal/collector"

// newPlatformImageLoadCollector is a no-op here: this file covers macOS, and
// Linux builds without the eBPF tag (which fall back to /proc polling and have
// no dlopen visibility). The Linux eBPF dlopen collector lives in
// imageload_linux_ebpf.go; image-load telemetry is otherwise Windows-only (ETW).
func newPlatformImageLoadCollector() collector.ImageLoadCollector {
	return nil
}

// newPlatformScriptCollector is a no-op on non-Windows platforms; script-content
// telemetry is currently Windows-only (PowerShell/AMSI ETW).
func newPlatformScriptCollector() collector.ScriptContentCollector {
	return nil
}
