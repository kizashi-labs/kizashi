//go:build linux && ebpf && prevention

package linux

import (
	"context"
	"log/slog"

	"github.com/edr-platform/agent/internal/collector"
)

// runTLSMonitor delegates to LoadAndRunTLSMonitor (tls_ebpf_loader.go), compiled only
// with the "ebpf" tag. A load/attach failure disables JA3 capture but must not take down
// the agent, so it is logged and swallowed by the caller.
func runTLSMonitor(ctx context.Context, agentID string, sender collector.EventSender) error {
	err := LoadAndRunTLSMonitor(ctx, agentID, sender)
	if err != nil && ctx.Err() == nil {
		slog.Warn("eBPF TLS monitor failed to load/run; JA3/JA3S fingerprinting disabled", "error", err)
	}
	return err
}
