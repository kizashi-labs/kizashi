//go:build linux && ebpf && solib

package main

import (
	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
)

// newPlatformImageLoadCollector returns the Linux eBPF dlopen (.so load)
// collector when built with `-tags "ebpf solib"` (requires bpf2go artifacts
// generated on a clang+BTF host). The Linux counterpart to the Windows
// image_load ETW collector.
func newPlatformImageLoadCollector() collector.ImageLoadCollector {
	return linuxplat.NewEBPFLibraryCollector()
}

// newPlatformScriptCollector: script-content telemetry is Windows-only (ETW);
// nil on Linux even under the solib build. Defined here because imageload_other.go
// (which otherwise provides it for non-Windows) is excluded under this tag combo.
func newPlatformScriptCollector() collector.ScriptContentCollector {
	return nil
}
