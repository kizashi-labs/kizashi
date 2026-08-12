//go:build linux && ebpf && prevention

package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	linuxplat "github.com/edr-platform/agent/internal/platform/linux"
)

// runPreventionService runs the eBPF LSM exec-prevention service. It loads the
// LSM and seeds the blocklist from the same process_block deny rules the polling
// path uses (absolute-path rules only — exact-match in kernel), mapping each
// rule's action to a per-path mode: alert → audit-only, block/alert_and_block →
// enforce-eligible. A would-block decision is reported as a process_block event,
// reusing the existing rule source and event type (no server changes).
//
// The GLOBAL enforce switch is fail-open by default (audit-all: nothing is
// denied, everything reported) and is only turned on when EDR_PREVENTION_ENFORCE=1
// (Ph3 opt-in). So even block rules audit until an operator deliberately promotes
// to enforce, and alert rules never deny. Blocks until ctx is cancelled. On hosts
// without BPF LSM it logs and returns, leaving the agent in observe mode.
func runPreventionService(ctx context.Context, sender collector.EventSender, agentID, serverURL string) {
	runner := linuxplat.NewPreventionRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[prevention] eBPF LSM未起動（LSM非対応/未許可ホスト） — observeモード継続", "error", err)
		return
	}
	defer runner.Close()

	enforce := os.Getenv("EDR_PREVENTION_ENFORCE") == "1"
	if err := runner.SetEnforce(enforce); err != nil {
		slog.Warn("[prevention] enforceスイッチ設定失敗", "error", err)
	}
	mode := "audit（fail-open: 拒否しない）"
	if enforce {
		mode = "enforce（block ルールを -EPERM 拒否）"
	}
	slog.Info("[prevention] eBPF LSM 実行前防御を起動しました", "mode", mode)

	var mu sync.Mutex
	ruleByPath := map[string]collector.ProcessBlockRule{}

	refresh := func() {
		rules, err := collector.FetchProcessBlockRules(ctx, serverURL, agentID)
		if err != nil {
			slog.Debug("[prevention] ルール取得失敗", "error", err)
			return
		}
		entries := make(map[string]uint8, len(rules))
		m := make(map[string]collector.ProcessBlockRule, len(rules))
		for _, r := range rules {
			// LSM prevention covers deny rules whose process_name is an absolute
			// path (kernel match is exact-path). Name/glob rules stay with the
			// polling path on non-LSM hosts.
			if r.RuleType != "deny" || !strings.HasPrefix(r.ProcessName, "/") {
				continue
			}
			// action=block/alert_and_block → enforce-eligible; alert → audit-only.
			modeVal := linuxplat.PathModeAudit
			if r.Action == "block" || r.Action == "alert_and_block" {
				modeVal = linuxplat.PathModeEnforce
			}
			entries[r.ProcessName] = modeVal
			m[r.ProcessName] = r
		}
		if err := runner.UpdateBlocklist(entries); err != nil {
			slog.Warn("[prevention] blocklist更新失敗", "error", err)
			return
		}
		mu.Lock()
		ruleByPath = m
		mu.Unlock()
		slog.Debug("[prevention] blocklist更新完了", "count", len(entries))
	}
	refresh()

	decisions := make(chan linuxplat.PreventionDecision, 64)
	go runner.Run(ctx, decisions)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		case d := <-decisions:
			mu.Lock()
			r := ruleByPath[d.Filename]
			mu.Unlock()
			// action reflects the actual kernel decision: enforced → "block"
			// (exec denied with -EPERM), otherwise → "audit" (reported, allowed).
			// Visible via the existing server-side process_block ingestion.
			action, verdict := "audit", "実行を許可（audit/fail-open）"
			if d.Enforced {
				action, verdict = "block", "実行を拒否（enforce, -EPERM）"
			}
			batch := collector.BuildProcessBlockEvent(agentID,
				collector.ProcessBlockPayload(d.Filename, int(d.PID), action, r.ID, r.Name, r.Severity))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Info("[prevention] 実行前防御判定", "path", d.Filename, "pid", d.PID, "rule", r.Name, "verdict", verdict)
		}
	}
}
