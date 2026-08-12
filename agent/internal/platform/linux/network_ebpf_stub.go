//go:build linux && !ebpf

package linux

import (
	"context"
	"errors"

	"github.com/edr-platform/agent/internal/collector"
)

// runEBPFNetworkMonitor is a no-op stub when the "ebpf" build tag is absent; the
// caller (EBPFNetworkCollector.Start) degrades to /proc/net polling. Silent by
// design — a non-ebpf build has no eBPF to load.
func runEBPFNetworkMonitor(_ context.Context, _ chan<- collector.NetworkEvent) error {
	return errors.New("eBPF network monitor not built (no 'ebpf' tag)")
}
