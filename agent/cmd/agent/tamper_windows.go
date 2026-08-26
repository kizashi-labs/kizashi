//go:build windows && prevention

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/edr-platform/agent/internal/collector"
	winplat "github.com/edr-platform/agent/internal/platform/windows"
	"github.com/edr-platform/agent/internal/tamper"
)

// runTamperService runs Windows agent self-protection — the counterpart of the
// Linux eBPF LSM task_kill path (tamper_linux.go). It registers the agent PID
// with the KizashiPrevention driver, whose ObRegisterCallbacks pre-operation
// callback strips kill/inject/suspend access (PROCESS_TERMINATE etc.) from
// handles opened to the agent.
//
// Enforce is opt-in via EDR_TAMPER_ENFORCE=1 (fail-open default: audit-only —
// attempts are recorded but access is not stripped). Because enforcing would also
// block the agent's own legitimate stop, there are two escape hatches: (1) on a
// graceful stop (ctx cancelled by the SCM/Ctrl-C) the agent disarms before
// exiting; (2) stopping the driver service (`sc stop KizashiPrevention`)
// unregisters the callback, so an operator can always recover. Blocks until ctx
// is cancelled; if the driver is not loaded it logs and returns.
func runTamperService(ctx context.Context, sender collector.EventSender, agentID string) {
	client := winplat.NewTamperClient()
	if err := client.Start(); err != nil {
		slog.Info("[tamper] KizashiPrevention ドライバ未ロード — 自己保護なしで継続", "error", err)
		return
	}
	defer client.Close()

	enforce := os.Getenv("EDR_TAMPER_ENFORCE") == "1"
	if err := client.SetEnforce(enforce); err != nil {
		slog.Warn("[tamper] enforceスイッチ設定失敗", "error", err)
	}
	_ = client.SetDisarm(false) // armed at start

	self := uint32(os.Getpid())
	if err := client.ProtectPID(self, winplat.PathModeEnforce); err != nil {
		slog.Warn("[tamper] 保護PID登録失敗", "error", err)
		return
	}
	mode := "audit（検知のみ・許可）"
	if enforce {
		mode = "enforce（agentへのPROCESS_TERMINATE等を剥奪、解除は sc stop KizashiPrevention）"
	}
	slog.Info("[tamper] エージェント自己保護(Obコールバック)を起動しました", "mode", mode, "protected_pid", self)

	decisions := make(chan winplat.TamperDecision, 32)
	go client.Run(ctx, decisions)

	for {
		select {
		case <-ctx.Done():
			// Graceful stop: disarm so the service can be stopped/updated.
			_ = client.SetDisarm(true)
			return
		case d := <-decisions:
			verdict := "検知のみ（許可）"
			if d.Enforced {
				verdict = "拒否（kill/inject 権限を剥奪）"
			}
			slog.Warn("[tamper] エージェントへのハンドルオープン試行を検知",
				"target_pid", d.TargetPID,
				"sender_pid", d.SenderPID,
				"access", fmt.Sprintf("0x%x", d.Access),
				"verdict", verdict)

			// Until now this finding only reached the local log file — on the host
			// the attacker is trying to silence. Ship it.
			payload := tamper.New(tamper.TypeHandleOpenAttempt, tamper.ComponentAgent, d.Enforced).
				WithTarget(int(d.TargetPID)).
				WithSource(int(d.SenderPID), "", "").
				WithAccessMask(fmt.Sprintf("0x%x", d.Access)).
				WithReason(verdict)
			if batch := collector.BuildTamperEvent(agentID, payload); batch != nil {
				if err := sender.SendEvents(ctx, batch); err != nil {
					slog.Warn("[tamper] ハンドルオープン試行の送信に失敗しました", "error", err)
				}
			}
		}
	}
}
