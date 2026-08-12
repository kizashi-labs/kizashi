//go:build linux && ebpf

package linux

import (
	"context"
	"log/slog"

	"github.com/edr-platform/agent/internal/collector"
)

// runEBPFNetworkMonitor delegates to LoadAndRunEBPFNetworkMonitor (network_ebpf_loader.go),
// compiled only with the "ebpf" tag. A load/attach failure is unexpected (kprobe
// tcp_connect is stable), so log it before the caller degrades to /proc polling.
func runEBPFNetworkMonitor(ctx context.Context, out chan<- collector.NetworkEvent) error {
	err := LoadAndRunEBPFNetworkMonitor(ctx, out)
	if err != nil && ctx.Err() == nil {
		slog.Warn("eBPF network monitor failed to load/run; falling back to /proc/net polling", "error", err)
	}
	return err
}
