//go:build linux && !ebpf

package linux

import (
	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/telemetry"
)

// NewFileCollector returns the inotify file collector in non-eBPF builds. It reports
// file changes but cannot attribute them to a process (inotify carries no pid), so the
// per-process ransomware detector stays inert — build with `-tags ebpf` for attribution.
func NewFileCollector() collector.FileCollector {
	// A build without the ebpf tag has no eBPF file collector to fall back FROM,
	// so nothing on the runtime path would ever report this sensor — which is how
	// the same degradation went unnoticed in production. Registering it here makes
	// the choice visible in the fleet: the mode is decided at compile time, so it
	// is known before the collector even starts.
	telemetry.Set(telemetrySensorFile, telemetry.ModePoll, "eBPFタグ無しビルド")
	return NewInotifyFileCollector()
}
