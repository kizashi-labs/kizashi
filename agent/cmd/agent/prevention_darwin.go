//go:build darwin && esf && prevention

package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	darwinplat "github.com/edr-platform/agent/internal/platform/darwin"
)

// runPreventionService runs the macOS ESF AUTH_EXEC prevention service — the
// macOS counterpart of prevention_linux.go / prevention_windows.go. It seeds the
// ESF client's blocklist from the same process_block deny rules (absolute paths;
// exact ESF executable path match), maps each rule's action to a per-path mode
// (alert → audit-only, block/alert_and_block → enforce-eligible), and reports
// each would-block as a process_block event (server-side ingestion verified in
// Ph2; no server changes).
//
// The GLOBAL enforce switch is fail-open by default and only on with
// EDR_PREVENTION_ENFORCE=1. If the ESF client can't start (missing entitlement /
// unsigned binary), it logs and returns, leaving the agent in observe mode.
//
// SCAFFOLD: builds only on macOS with `-tags "esf prevention"` and runs only with
// the ESF entitlement (Apple approval). See docs/macOS-ESF-entitlement申請キット.md.
func runPreventionService(ctx context.Context, sender collector.EventSender, agentID, serverURL string) {
	runner := darwinplat.NewPreventionRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[prevention] ESF AUTHクライアント未起動（entitlement未付与/未署名） — observeモード継続", "error", err)
		return
	}
	defer runner.Close()

	enforce := os.Getenv("EDR_PREVENTION_ENFORCE") == "1"
	if err := runner.SetEnforce(enforce); err != nil {
		slog.Warn("[prevention] enforceスイッチ設定失敗", "error", err)
	}
	mode := "audit（fail-open: 拒否しない）"
	if enforce {
		mode = "enforce（block ルールを ES_AUTH_RESULT_DENY 拒否）"
	}
	slog.Info("[prevention] macOS ESF 実行前防御を起動しました", "mode", mode)

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
			// ESF prevention covers deny rules whose process_name is an absolute
			// path (ESF reports the resolved executable path). Name/glob rules stay
			// with the polling path.
			if r.RuleType != "deny" || !strings.HasPrefix(r.ProcessName, "/") {
				continue
			}
			modeVal := darwinplat.PathModeAudit
			if r.Action == "block" || r.Action == "alert_and_block" {
				modeVal = darwinplat.PathModeEnforce
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

	decisions := make(chan darwinplat.PreventionDecision, 64)
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
			action, verdict := "audit", "実行を許可（audit/fail-open）"
			if d.Enforced {
				action, verdict = "block", "実行を拒否（enforce, ES_AUTH_RESULT_DENY）"
			}
			batch := collector.BuildProcessBlockEvent(agentID,
				collector.ProcessBlockPayload(d.Filename, d.PID, action, r.ID, r.Name, r.Severity))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Info("[prevention] 実行前防御判定", "path", d.Filename, "pid", d.PID, "rule", r.Name, "verdict", verdict)
		}
	}
}
