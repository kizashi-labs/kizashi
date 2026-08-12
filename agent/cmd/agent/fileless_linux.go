//go:build linux && ebpf

package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
)

// runFilelessService runs the eBPF fileless-execution sensor: it reports when a
// process executes code straight from a file descriptor via
// execveat(AT_EMPTY_PATH) — the memfd/reflective-loading pattern that leaves no
// file on disk (T1620 Reflective Code Loading / T1055 Process Injection). Each hit
// is emitted as a "memory" finding so it flows through the existing memory/
// injection detection path. Report-only. No-op on kernels without the tracepoints
// or without the `-tags ebpf` build.
func runFilelessService(ctx context.Context, sender collector.EventSender, agentID string) {
	runner := linuxplat.NewFilelessRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[fileless] eBPF未起動（tracepoint非対応/未許可） — fileless実行検知なしで継続", "error", err)
		return
	}
	defer runner.Close()
	slog.Info("[fileless] fileless実行検知(execveat AT_EMPTY_PATH / memfd_create)を起動しました")

	self := uint32(os.Getpid())
	events := make(chan linuxplat.FilelessEvent, 64)
	go runner.Run(ctx, events)

	// Dedup a process's repeated fileless-exec hits within a short window.
	seen := make(map[uint32]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			// Only the actual fileless execution (execveat AT_EMPTY_PATH, kind=2) is
			// a high-fidelity signal; memfd_create alone (kind=1) is too common to
			// alert on and is ignored here.
			if ev.Kind != 2 || ev.PID == self {
				continue
			}
			now := time.Now()
			if last, ok := seen[ev.PID]; ok && now.Sub(last) < 30*time.Second {
				continue
			}
			if len(seen) > 1024 {
				seen = make(map[uint32]time.Time)
			}
			seen[ev.PID] = now

			f := collector.MemoryFinding{
				PID:         int(ev.PID),
				ProcessName: ev.Comm,
				Unbacked:    true, // fileless code has no on-disk backing
				Reason:      "fileless実行: execveat(AT_EMPTY_PATH)=メモリ/fdから直接実行(T1620/T1055)",
			}
			if batch := collector.BuildMemoryEvent(agentID, f); batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Warn("[fileless] fileless実行を検知(T1620/T1055)", "pid", ev.PID, "process", ev.Comm)
		}
	}
}
