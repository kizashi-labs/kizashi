//go:build linux && ebpf

package linux

import (
	"context"
	"log/slog"

	"github.com/edr-platform/agent/internal/collector"
)

// runEBPFProcessMonitor delegates to LoadAndRunEBPFProcessMonitor from
// ebpf_loader.go, which is only compiled when the "ebpf" build tag is set.
// A load/verifier failure here (unlike the silent stub) is unexpected, so log
// it before the caller degrades to /proc polling. A clean ctx cancellation is
// not an error worth logging.
func runEBPFProcessMonitor(ctx context.Context, out chan<- collector.ProcessEvent) error {
	err := LoadAndRunEBPFProcessMonitor(ctx, out)
	if err != nil && ctx.Err() == nil {
		slog.Warn("eBPF process monitor failed to load/run; falling back to /proc polling", "error", err)
	}
	return err
}
