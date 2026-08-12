//go:build linux

package linux

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/telemetry"
)

// EBPFNetworkCollector implements collector.NetworkCollector. When eBPF is
// available (kernel >= 5.8, built with the "ebpf" tag) it streams every outbound
// TCP connect ATTEMPT via kprobe/tcp_connect — including connections to closed
// ports that /proc/net polling never captures (the poller only ever sees
// ESTABLISHED sockets, so scans of closed ports are invisible). That connect-level
// telemetry is what the server-side port-scan / fan-out detector needs to fire
// (T1046; see docs/results/live-20260702-linux-evasion-adversarial.md). Falls back
// to /proc/net polling when eBPF is unavailable or the tag is absent.
type EBPFNetworkCollector struct {
	useEBPF  bool
	fallback *ProcNetCollector
	cancel   context.CancelFunc
}

// NewEBPFNetworkCollector returns a network collector that prefers eBPF connect
// tracing and degrades to /proc/net polling.
func NewEBPFNetworkCollector() *EBPFNetworkCollector {
	return &EBPFNetworkCollector{
		useEBPF:  isEBPFSupported(),
		fallback: NewProcNetCollector(),
	}
}

// Start begins streaming network events. When eBPF loads, it runs the connect
// tracer (blocking until ctx is cancelled, like the process monitor); on setup
// failure or without the ebpf tag it degrades to /proc/net polling. Start is
// invoked from a goroutine by the agent, so blocking here is expected.
func (c *EBPFNetworkCollector) Start(ctx context.Context, out chan<- collector.NetworkEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	if c.useEBPF {
		// runEBPFNetworkMonitor blocks while streaming; it only returns early on a
		// load/attach failure, in which case we degrade to polling.
		telemetry.Set(telemetrySensorNetwork, telemetry.ModeEBPF, "")
		err := runEBPFNetworkMonitor(ctx, out)
		if err == nil {
			return nil
		}
		// A cancelled context is an orderly shutdown, not a degradation.
		if ctx.Err() != nil {
			return nil
		}
		degradeToPolling(telemetrySensorNetwork, err,
			"接続試行(SYN)が見えず、閉ポートへのスキャン(T1046)を検知できません")
	} else {
		degradeToPolling(telemetrySensorNetwork, errEBPFUnsupported,
			"接続試行(SYN)が見えず、閉ポートへのスキャン(T1046)を検知できません")
	}
	return c.fallback.Start(ctx, out)
}

// Stop cancels the collector.
func (c *EBPFNetworkCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return c.fallback.Stop()
}
