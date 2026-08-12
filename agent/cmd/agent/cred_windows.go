//go:build windows && prevention

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	winplat "github.com/edr-platform/agent/internal/platform/windows"
	syswin "golang.org/x/sys/windows"
)

// runCredService runs LSASS credential-access detection (M3). It registers the
// lsass.exe PID with the KizashiPrevention driver, whose ObRegisterCallbacks
// pre-operation callback records (and, when enforcing, strips) PROCESS_VM_READ
// opens of lsass — the LSASS-memory read used by credential dumpers
// (mimikatz/procdump, ATT&CK T1003.001). Each non-allowlisted decision is emitted
// as a credential_access event the server turns into an alert.
//
// Enforce is opt-in via EDR_CRED_ENFORCE=1 (fail-open default: audit-only). An
// allowlist of AV/system processes (and the agent itself) that legitimately read
// LSASS cuts false positives. Stopping the driver service unregisters the
// callback; on graceful stop the watch is disabled. No-op if the driver is not
// loaded.
func runCredService(ctx context.Context, sender collector.EventSender, agentID string) {
	client := winplat.NewCredClient()
	if err := client.Start(); err != nil {
		slog.Info("[cred] KizashiPrevention ドライバ未ロード — LSASS監視なしで継続", "error", err)
		return
	}
	defer client.Close()

	lsassPID := findLsassPID()
	if lsassPID == 0 {
		slog.Warn("[cred] lsass.exe PID を特定できませんでした")
		return
	}

	enforce := os.Getenv("EDR_CRED_ENFORCE") == "1"
	_ = client.SetEnforce(enforce)
	mode := winplat.PathModeAudit
	modeStr := "audit（検知のみ・許可）"
	if enforce {
		mode = winplat.PathModeEnforce
		modeStr = "enforce（lsassへのPROCESS_VM_READを剥奪）"
	}
	if err := client.WatchLsass(uint32(lsassPID), mode); err != nil {
		slog.Warn("[cred] lsass PID登録失敗", "error", err)
		return
	}
	slog.Info("[cred] LSASS認証情報アクセス検知(Obコールバック)を起動しました", "mode", modeStr, "lsass_pid", lsassPID)

	// Processes that legitimately open LSASS with VM_READ (AV/EDR/system) — and the
	// agent itself — are allowlisted to cut false positives.
	allow := map[string]bool{
		"system": true, "wininit.exe": true, "services.exe": true, "csrss.exe": true,
		"svchost.exe": true, "lsass.exe": true, "msmpeng.exe": true, "mssense.exe": true,
		"sensendr.exe": true, "wmiprvse.exe": true, "searchindexer.exe": true,
	}
	selfBase := strings.ToLower(filepath.Base(os.Args[0]))

	decisions := make(chan winplat.CredDecision, 64)
	go client.Run(ctx, decisions)

	const credDedupTTL = 5 * time.Minute
	seen := make(map[string]time.Time, 1024)
	for {
		select {
		case <-ctx.Done():
			_ = client.WatchLsass(0, 0) // disable the watch on graceful stop
			return
		case d := <-decisions:
			if d.SenderPID <= 4 {
				continue // System / Idle
			}
			sname := strings.ToLower(winplat.ProcessImageName(uint32(d.SenderPID)))
			if sname == "" || allow[sname] || sname == selfBase {
				continue // trusted reader of LSASS
			}
			key := fmt.Sprintf("%d->%d", d.SenderPID, d.TargetPID)
			now := time.Now()
			if last, ok := seen[key]; ok && now.Sub(last) < credDedupTTL {
				continue
			}
			if len(seen) > 8192 {
				seen = make(map[string]time.Time, 1024)
			}
			seen[key] = now

			batch := collector.BuildCredentialAccessEvent(agentID,
				collector.CredentialAccessPayload(d.TargetPID, "lsass.exe", d.SenderPID, sname,
					fmt.Sprintf("0x%x", d.Access), d.Enforced))
			if batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
			slog.Warn("[cred] LSASS認証情報アクセスを検知",
				"accessor", sname, "accessor_pid", d.SenderPID, "lsass_pid", d.TargetPID,
				"access", fmt.Sprintf("0x%x", d.Access), "enforced", d.Enforced)
		}
	}
}

// findLsassPID returns the PID of lsass.exe via a Toolhelp32 snapshot, or 0.
func findLsassPID() int {
	snap, err := syswin.CreateToolhelp32Snapshot(syswin.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer syswin.CloseHandle(snap)
	var e syswin.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := syswin.Process32First(snap, &e); err != nil {
		return 0
	}
	for {
		if strings.EqualFold(syswin.UTF16ToString(e.ExeFile[:]), "lsass.exe") {
			return int(e.ProcessID)
		}
		if err := syswin.Process32Next(snap, &e); err != nil {
			return 0
		}
	}
}
