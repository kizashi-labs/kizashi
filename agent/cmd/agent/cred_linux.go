//go:build linux && ebpf && prevention

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
	"github.com/edr-platform/agent/internal/telemetry"
)

// sensorCredAccess — ハートビートに載るセンサー名。Windows 側の
// cred_lsass と対になります（どちらも「資格情報アクセスを見ているか」）。
const sensorCredAccess = "cred_access"

// runCredService runs Linux credential/memory-access detection: an eBPF LSM
// ptrace_access_check hook reports when a process reads another process's memory
// (gdb -p, open of /proc/<pid>/mem, process_vm_readv) — the Linux equivalent of
// the Windows LSASS-access sensor. It emits credential_access events (T1003
// credential dumping, T1055 process injection). Audit-only (never denies). No-op
// on hosts without BPF LSM. Built only with `-tags "ebpf prevention"`.
func runCredService(ctx context.Context, sender collector.EventSender, agentID string) {
	runner := linuxplat.NewCredAccessRunner()
	if err := runner.Start(); err != nil {
		// **slog.Info で抜けていました。** ログはその端末の中にしか残らない
		// ので、SOC からは「資格情報アクセスを見ていない端末」を数えられ
		// ません。イベントが来ないのは、攻撃されていないからなのか、
		// センサーが上がらなかったからなのか、外からは同じ姿をします。
		//
		// ModeOff ではなく ModeFailed です。`-tags "ebpf prevention"` で
		// 焼いた上でここまで来ているので、**望んだのに届かなかった**方です。
		telemetry.Set(sensorCredAccess, telemetry.ModeFailed,
			"eBPF LSM 未起動（LSM非対応/未許可ホスト）: "+err.Error())
		slog.Warn("[credaccess] eBPF LSM未起動（LSM非対応/未許可ホスト） — "+
			"**この端末では資格情報アクセスを見ていません**", "error", err)
		return
	}
	defer runner.Close()
	// 上がったので、前回の失敗は消します。直らない赤は赤でないのと同じです。
	telemetry.Forget(sensorCredAccess)
	slog.Info("[credaccess] プロセスメモリアクセス検知(ptrace_access_check)を起動しました")

	self := uint32(os.Getpid())
	events := make(chan linuxplat.CredAccessEvent, 64)
	go runner.Run(ctx, events)

	// Light dedup: suppress repeats of the same tracer→target within a short
	// window so a debugger's many reads become one signal. Bounded to avoid growth.
	type seenKey struct{ tracer, target uint32 }
	seen := make(map[seenKey]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			if ev.TracerPID == self {
				continue // ignore the agent's own accesses
			}
			k := seenKey{ev.TracerPID, ev.TargetPID}
			now := time.Now()
			if last, ok := seen[k]; ok && now.Sub(last) < 10*time.Second {
				continue
			}
			if len(seen) > 1024 {
				seen = make(map[seenKey]time.Time)
			}
			seen[k] = now

			mask := fmt.Sprintf("ptrace_mode=0x%x", ev.Mode)
			batch := collector.BuildCredentialAccessEvent(agentID,
				collector.CredentialAccessPayload(int(ev.TargetPID), ev.TargetComm, int(ev.TracerPID), ev.TracerComm, mask, false))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Warn("[credaccess] プロセスメモリアクセスを検知(T1003/T1055)",
				"tracer", ev.TracerComm, "tracer_pid", ev.TracerPID,
				"target", ev.TargetComm, "target_pid", ev.TargetPID, "mode", mask)
		}
	}
}
