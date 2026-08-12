//go:build linux && ebpf && prevention

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
	"github.com/edr-platform/agent/internal/tamper"
)

// runTamperService runs agent self-protection: an eBPF LSM task_kill hook
// reports (audit) or denies (enforce) attempts to KILL the agent process.
//
// Enforce is opt-in via EDR_TAMPER_ENFORCE=1 (fail-open default: audit). Because
// denying kills to the agent would also block its legitimate stop (systemctl /
// SIGTERM from PID 1) — the self-lock the design (§3-2) warns about — a DISARM
// escape hatch is wired to SIGUSR1: `kill -USR1 <agent>` temporarily allows kills
// so an operator can stop/update/uninstall. The BPF link is not pinned, so it
// auto-detaches if the agent dies (fail-safe: never permanently locks the OS).
// Blocks until ctx is cancelled; on hosts without BPF LSM it logs and returns.
func runTamperService(ctx context.Context, sender collector.EventSender, agentID string) {
	runner := linuxplat.NewTamperRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[tamper] eBPF LSM未起動（LSM非対応/未許可ホスト） — 自己保護なしで継続", "error", err)
		return
	}
	defer runner.Close()

	enforce := os.Getenv("EDR_TAMPER_ENFORCE") == "1"
	if err := runner.SetEnforce(enforce); err != nil {
		slog.Warn("[tamper] enforceスイッチ設定失敗", "error", err)
	}
	_ = runner.SetDisarm(false) // armed at start

	self := uint32(os.Getpid())
	if err := runner.ProtectPID(self, linuxplat.PathModeEnforce); err != nil {
		slog.Warn("[tamper] 保護PID登録失敗", "error", err)
		return
	}
	mode := "audit（検知のみ・許可）"
	if enforce {
		mode = "enforce（agentへのkillを-EPERM拒否、解除はSIGUSR1）"
	}
	slog.Info("[tamper] エージェント自己保護(task_kill)を起動しました", "mode", mode, "protected_pid", self)

	// SIGUSR1 disarms (legitimate stop/update escape hatch). SIGUSR1 is not in the
	// guarded signal set, so it always reaches the agent even under enforce.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	defer signal.Stop(usr1)

	decisions := make(chan linuxplat.TamperDecision, 32)
	go runner.Run(ctx, decisions)

	for {
		select {
		case <-ctx.Done():
			return
		case <-usr1:
			if err := runner.SetDisarm(true); err != nil {
				slog.Warn("[tamper] disarm設定失敗", "error", err)
			} else {
				slog.Warn("[tamper] SIGUSR1受信 — 自己保護を一時解除（disarm）。以降のkillは許可されます")
			}
		case d := <-decisions:
			verdict := "検知のみ（許可）"
			if d.Enforced {
				verdict = "拒否（enforce, -EPERM）"
			}
			slog.Warn("[tamper] エージェントへのkill試行を検知",
				"target_pid", d.TargetPID,
				"sender_pid", d.SenderPID,
				"sender_uid", d.SenderUID,
				"sender", d.SenderComm,
				"signal", d.Sig,
				"verdict", verdict)

			// Until now this finding only reached the local log file — on the host
			// the attacker is trying to silence. Ship it.
			payload := tamper.New(tamper.TypeKillAttempt, tamper.ComponentAgent, d.Enforced).
				WithTarget(int(d.TargetPID)).
				WithSource(int(d.SenderPID), d.SenderComm, fmt.Sprintf("uid=%d", d.SenderUID)).
				WithSignal(int(d.Sig)).
				WithReason(verdict)
			if batch := collector.BuildTamperEvent(agentID, payload); batch != nil {
				if err := sender.SendEvents(ctx, batch); err != nil {
					slog.Warn("[tamper] kill試行の送信に失敗しました", "error", err)
				}
			}
		}
	}
}
