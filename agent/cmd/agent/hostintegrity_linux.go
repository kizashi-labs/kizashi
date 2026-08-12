//go:build linux && ebpf && prevention

package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
)

// runHostIntegrityService runs the eBPF host-integrity sensor: it reports
// kernel-module loads (init_module/finit_module, T1547.006), namespace
// manipulation (unshare/setns, T1611 container/host escape), and capability
// changes (capset, T1548.001) at the syscall level — independent of which
// binary or command-line text invoked them (the insmod/nsenter/chmod-+s rules
// in sigma_builtins.go/migration 309 all key on CommandLine, so a custom or
// renamed binary calling the syscall directly bypasses them). Report-only. No-op
// on kernels without the tracepoints or without the `-tags "ebpf prevention"`
// build.
func runHostIntegrityService(ctx context.Context, sender collector.EventSender, agentID string) {
	runner := linuxplat.NewHostIntegrityRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[hostintegrity] eBPF未起動（tracepoint非対応/未許可） — カーネルモジュール/namespace/capability検知なしで継続", "error", err)
		return
	}
	defer runner.Close()
	slog.Info("[hostintegrity] ホスト整合性検知(カーネルモジュール/namespace/capability)を起動しました")

	self := uint32(os.Getpid())
	events := make(chan linuxplat.HostIntegrityEvent, 64)
	go runner.Run(ctx, events)

	// Dedup a process's repeated hits of the same kind within a short window.
	type seenKey struct {
		pid  uint32
		kind linuxplat.HostIntegrityKind
	}
	seen := make(map[seenKey]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			if ev.PID == self {
				continue
			}

			k := seenKey{ev.PID, ev.Kind}
			now := time.Now()
			if last, ok := seen[k]; ok && now.Sub(last) < 30*time.Second {
				continue
			}
			if len(seen) > 1024 {
				seen = make(map[seenKey]time.Time)
			}
			seen[k] = now

			action, technique := hostIntegrityActionAndTechnique(ev.Kind)
			batch := collector.BuildHostIntegrityEvent(agentID,
				collector.HostIntegrityPayload(action, int(ev.PID), ev.Comm, ev.CommandLine))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Warn("[hostintegrity] ホスト整合性イベントを検知("+technique+")",
				"action", action, "pid", ev.PID, "process", ev.Comm, "command_line", ev.CommandLine)
		}
	}
}

// hostIntegrityActionAndTechnique maps a syscall kind to the action string
// Sigma rules select on and a human-readable MITRE technique label for logs.
func hostIntegrityActionAndTechnique(kind linuxplat.HostIntegrityKind) (action, technique string) {
	switch kind {
	case linuxplat.HostIntegrityInitModule, linuxplat.HostIntegrityFinitModule:
		return "kernel_module_load", "T1547.006"
	case linuxplat.HostIntegrityUnshare, linuxplat.HostIntegritySetns:
		return "namespace_manipulation", "T1611"
	case linuxplat.HostIntegrityCapset:
		return "capability_set", "T1548.001"
	default:
		return "unknown", ""
	}
}
