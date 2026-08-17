//go:build linux && ebpf

package main

import (
	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
)

// newPlatformImageLoadCollector returns the Linux eBPF dlopen (.so load)
// collector — the Linux counterpart to the Windows image_load ETW collector.
// Wired into every `-tags ebpf` build, which is what ci.yml and server/Dockerfile
// produce. It was previously behind an extra `solib` tag that nothing built.
func newPlatformImageLoadCollector() collector.ImageLoadCollector {
	return linuxplat.NewEBPFLibraryCollector()
}

// newPlatformScriptCollector: script-content telemetry is Windows-only (ETW);
// nil on Linux even under the eBPF build. Defined here because imageload_other.go
// (which otherwise provides it for non-Windows) is excluded under this tag combo.
func newPlatformScriptCollector() collector.ScriptContentCollector {
	return nil
}
