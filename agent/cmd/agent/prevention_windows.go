//go:build windows && prevention

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	winplat "github.com/edr-platform/agent/internal/platform/windows"
)

// runPreventionService runs the Windows kernel-driver exec-prevention service —
// the Windows counterpart of the Linux eBPF LSM path (prevention_linux.go). It
// opens the KizashiPrevention driver, seeds its blocklist from the same
// process_block deny rules the polling path uses, maps each rule's action to a
// per-path mode (alert → audit-only, block/alert_and_block → enforce-eligible),
// and reports each would-block as a process_block event — reusing the existing
// rule source and event type (server-side ingestion verified in Ph2; no server
// changes).
//
// The GLOBAL enforce switch is fail-open by default (audit-all: nothing denied,
// everything reported) and only turned on when EDR_PREVENTION_ENFORCE=1. If the
// driver is not loaded, it logs and returns, leaving the agent in observe mode.
// Blocks until ctx is cancelled.
//
// W1 NOTE: the kernel matches by case-insensitive suffix of the image's NT path.
// Bare-filename rules ("cmd.exe") are pushed as "\cmd.exe" to match the final
// component; absolute-path rules are pushed as-is (the NT path is "\??\" + the
// DOS path, so the DOS path is a suffix when names align). Glob rules stay with
// the polling path. Strict NT→DOS normalization (8.3 short names etc.) is W2.
func runPreventionService(ctx context.Context, sender collector.EventSender, agentID, serverURL string) {
	runner := winplat.NewPreventionRunner()
	if err := runner.Start(); err != nil {
		slog.Info("[prevention] KizashiPrevention ドライバ未ロード — observeモード継続", "error", err)
		return
	}
	defer runner.Close()

	enforce := os.Getenv("EDR_PREVENTION_ENFORCE") == "1"
	if err := runner.SetEnforce(enforce); err != nil {
		slog.Warn("[prevention] enforceスイッチ設定失敗", "error", err)
	}
	mode := "audit（fail-open: 拒否しない）"
	if enforce {
		mode = "enforce（block ルールを STATUS_ACCESS_DENIED 拒否）"
	}
	slog.Info("[prevention] Windows カーネル実行前防御を起動しました", "mode", mode)

	type ruleEntry struct {
		suffix string
		rule   collector.ProcessBlockRule
	}
	var mu sync.Mutex
	var entries []ruleEntry

	refresh := func() {
		rules, err := collector.FetchProcessBlockRules(ctx, serverURL, agentID)
		if err != nil {
			slog.Debug("[prevention] ルール取得失敗", "error", err)
			return
		}
		blocklist := make(map[string]uint8, len(rules))
		list := make([]ruleEntry, 0, len(rules))
		for _, r := range rules {
			if r.RuleType != "deny" {
				continue
			}
			aliases := expandAliases(r.ProcessName)
			if len(aliases) == 0 {
				continue // empty or glob — polling path covers globs
			}
			modeVal := winplat.PathModeAudit
			if r.Action == "block" || r.Action == "alert_and_block" {
				modeVal = winplat.PathModeEnforce
			}
			for _, suffix := range aliases {
				blocklist[suffix] = modeVal
				list = append(list, ruleEntry{suffix: suffix, rule: r})
			}
		}
		if err := runner.UpdateBlocklist(blocklist); err != nil {
			slog.Warn("[prevention] blocklist更新失敗", "error", err)
			return
		}
		mu.Lock()
		entries = list
		mu.Unlock()
		slog.Debug("[prevention] blocklist更新完了", "count", len(blocklist))
	}
	refresh()

	decisions := make(chan winplat.PreventionDecision, 64)
	go runner.Run(ctx, decisions)

	// M2 injection telemetry: audit cross-process injection operations (handle
	// opens with VM_WRITE/CREATE_THREAD + remote-thread creation) and surface them
	// as memory(T1055) events — the operation-side complement to M1's region scan.
	// Default on; set EDR_INJECT_AUDIT=0 to disable.
	if os.Getenv("EDR_INJECT_AUDIT") != "0" {
		if err := runner.SetInjectAudit(true); err != nil {
			slog.Warn("[prevention] 注入監査の有効化失敗", "error", err)
		} else {
			slog.Info("[prevention] M2 注入テレメトリを有効化しました")
			injects := make(chan winplat.InjectDecision, 64)
			go runner.RunInject(ctx, injects)
			go func() {
				const procVMWrite = 0x0020 // PROCESS_VM_WRITE
				// Trusted system/security processes legitimately open cross-process
				// handles constantly — allowlist them to cut M2 false positives.
				injectAllow := map[string]bool{
					"system": true, "registry": true, "memcompression": true,
					"csrss.exe": true, "lsass.exe": true, "services.exe": true,
					"wininit.exe": true, "smss.exe": true, "svchost.exe": true,
					"msmpeng.exe": true, "wmiprvse.exe": true, "searchindexer.exe": true,
					"conhost.exe": true, // hosts consoles; opens cross-process handles legitimately
				}
				const injectDedupTTL = 5 * time.Minute
				seen := make(map[string]time.Time, 1024) // dedup per sender→target (TTL)
				for {
					select {
					case <-ctx.Done():
						return
					case d := <-injects:
						// Only real injection signals: memory write or remote thread
						// (a bare VM_OPERATION open is too weak/common to alert on).
						if !d.RemoteThread && d.Access&procVMWrite == 0 {
							continue
						}
						if d.SenderPID <= 4 {
							continue // System / Idle
						}
						key := fmt.Sprintf("%d->%d", d.SenderPID, d.TargetPID)
						now := time.Now()
						if last, ok := seen[key]; ok && now.Sub(last) < injectDedupTTL {
							continue // same pair seen recently — re-alert only after the TTL
						}
						if len(seen) > 8192 {
							seen = make(map[string]time.Time, 1024)
						}
						seen[key] = now

						sname := strings.ToLower(winplat.ProcessImageName(uint32(d.SenderPID)))
						if injectAllow[sname] {
							continue // trusted injector
						}

						// Suppress the benign parent→child launch. A process creating the
						// INITIAL thread of a child it just spawned looks identical to a
						// CreateRemoteThread injection at the kernel callback (sender≠target),
						// so every normal process launch (powershell→systeminfo, →certutil, …)
						// was firing a false "remote thread injection". If the target's parent
						// is the sender, it is process creation, not injection — Sysmon EID8
						// excludes this case too. (A short-lived child that already exited
						// can't be checked and falls through; the 5-min per-pair dedup bounds
						// the residual noise.)
						if d.RemoteThread {
							if ppid := winplat.ProcessParentPID(uint32(d.TargetPID)); ppid != 0 && int(ppid) == d.SenderPID {
								continue
							}
						}

						// M1 correlation: scan the target — if it now has an RWX /
						// unbacked-executable region, the injected payload likely
						// landed (operation + artifact = high confidence).
						confirmed := false
						for _, mf := range collector.ScanProcessMemory(d.TargetPID) {
							if mf.RWX || mf.Unbacked {
								confirmed = true
								break
							}
						}

						reason := fmt.Sprintf("プロセスインジェクション疑い: %s(pid%d) → pid%d (access=0x%x)",
							sname, d.SenderPID, d.TargetPID, d.Access)
						if d.RemoteThread {
							reason = fmt.Sprintf("リモートスレッド生成(CreateRemoteThread): %s(pid%d) → pid%d",
								sname, d.SenderPID, d.TargetPID)
						}
						if confirmed {
							reason = "高確度注入(操作+対象にRWX/非バック実行領域): " + reason
						}
						f := collector.MemoryFinding{
							PID:         d.TargetPID,
							ProcessName: fmt.Sprintf("%s->pid%d", sname, d.TargetPID),
							Perms:       "INJECT",
							Unbacked:    confirmed, // high-confidence -> server severity 7
							Reason:      reason,
						}
						if batch := collector.BuildMemoryEvent(agentID, f); batch != nil {
							_ = sender.SendEvents(ctx, batch)
						}
						slog.Warn("[prevention] 注入操作を検知",
							"sender", sname, "sender_pid", d.SenderPID, "target", d.TargetPID,
							"access", fmt.Sprintf("0x%x", d.Access),
							"remote_thread", d.RemoteThread, "confirmed", confirmed)
					}
				}
			}()
		}
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		case d := <-decisions:
			// Find the rule whose suffix the decided NT path ends with.
			mu.Lock()
			var matched collector.ProcessBlockRule
			lower := strings.ToLower(d.Filename)
			for _, e := range entries {
				if strings.HasSuffix(lower, strings.ToLower(e.suffix)) {
					matched = e.rule
					break
				}
			}
			mu.Unlock()
			// action reflects the actual kernel decision: enforced → "block"
			// (creation denied), otherwise → "audit" (reported, allowed). Visible
			// via the existing server-side process_block ingestion.
			action, verdict := "audit", "実行を許可（audit/fail-open）"
			if d.Enforced {
				action, verdict = "block", "実行を拒否（enforce, STATUS_ACCESS_DENIED）"
			}
			batch := collector.BuildProcessBlockEvent(agentID,
				collector.ProcessBlockPayload(d.Filename, d.PID, action, matched.ID, matched.Name, matched.Severity))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Info("[prevention] 実行前防御判定", "path", d.Filename, "pid", d.PID, "rule", matched.Name, "verdict", verdict)
		}
	}
}

// expandAliases derives the driver match suffixes (case-insensitive suffixes of
// the image's NT path) for a rule's process_name:
//   - empty / glob ("*","?")  → nil (the polling path handles globs);
//   - bare filename           → ["\name.exe"] (match the final path component);
//   - drive-rooted path       → winplat.PathAliases: the DOS path plus its long,
//     8.3 short, and \Device\HarddiskVolumeN forms (W2 NT→DOS normalization);
//   - other path              → [path] as-is.
func expandAliases(processName string) []string {
	p := strings.TrimSpace(processName)
	if p == "" || strings.ContainsAny(p, "*?") {
		return nil
	}
	p = strings.ReplaceAll(p, "/", `\`)
	if !strings.Contains(p, `\`) {
		return []string{`\` + p} // bare filename → match final path component
	}
	if len(p) >= 2 && p[1] == ':' { // drive-rooted absolute path
		return winplat.PathAliases(p)
	}
	return []string{p}
}
