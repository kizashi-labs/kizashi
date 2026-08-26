//go:build windows && prevention

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	winplat "github.com/edr-platform/agent/internal/platform/windows"
	"github.com/edr-platform/agent/internal/telemetry"
	syswin "golang.org/x/sys/windows"
)

// sensorCredLsass — ハートビートに載るセンサー名。サーバの
// UpdateTelemetryMode が agents.telemetry_mode に書きます。
const sensorCredLsass = "cred_lsass"

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
		// ドライバが無い端末では、この関数は何もせず戻ります。**戻ったこと
		// を端末の外に出さないと、資格情報アクセスの監視が動いていない端末
		// を SOC から数えられません。** ログ1行はその端末の中にしか残らず、
		// 「攻撃されていない」と「見えていない」が同じ姿になります。
		telemetry.Set(sensorCredLsass, telemetry.ModeFailed,
			"KizashiPrevention ドライバ未ロード: "+err.Error())
		slog.Warn("[cred] KizashiPrevention ドライバ未ロード — LSASS監視なしで継続", "error", err)
		return
	}
	defer client.Close()

	lsassPID, err := findLsassPID()
	if err != nil {
		telemetry.Set(sensorCredLsass, telemetry.ModeFailed,
			"lsass.exe の PID を特定できません: "+err.Error())
		slog.Warn("[cred] lsass.exe PID を特定できませんでした。"+
			"**この端末では資格情報アクセスを見ていません**", "error", err)
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
	if err := client.WatchLsass(lsassPID, mode); err != nil {
		telemetry.Set(sensorCredLsass, telemetry.ModeFailed,
			"lsass PID をドライバに登録できません: "+err.Error())
		slog.Warn("[cred] lsass PID登録失敗", "error", err)
		return
	}
	// ここまで来たら見えています。前回の失敗が残っていると直っても赤い
	// ままなので、消します。
	telemetry.Forget(sensorCredLsass)
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

// findLsassPID returns the PID of lsass.exe via a Toolhelp32 snapshot.
//
// **0 を返していました。** スナップショットが取れなかった、先頭が読めな
// かった、走査が途中で終わった —— どれも同じ 0 で、呼び出し側からは
// 「lsass.exe が見つからなかった」と区別がつきません。
//
// その区別が効くのはここです。lsass.exe は Windows に必ずいるので、
// 「見つからない」は実際には起きません。**0 が返るときは、ほぼ必ず探せ
// なかったときです。** それを「対象なし」として黙って戻ると、資格情報
// アクセスの監視が丸ごと立ち上がっていない端末が、何も起きていない端末と
// 同じ姿になります —— イベントが来ない、アラートも出ない、画面は緑。
func findLsassPID() (uint32, error) {
	snap, err := syswin.CreateToolhelp32Snapshot(syswin.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("プロセス一覧のスナップショットを取れません: %w", err)
	}
	defer syswin.CloseHandle(snap)
	var e syswin.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := syswin.Process32First(snap, &e); err != nil {
		return 0, fmt.Errorf("プロセス一覧の先頭を読めません: %w", err)
	}
	for {
		if strings.EqualFold(syswin.UTF16ToString(e.ExeFile[:]), "lsass.exe") {
			return e.ProcessID, nil
		}
		if err := syswin.Process32Next(snap, &e); err != nil {
			// ERROR_NO_MORE_FILES は走査の正常な終わりです。ここに来たと
			// いうことは、最後まで見て lsass.exe が無かったということ ——
			// 走査そのものが途中で壊れたのとは別の話なので、分けます。
			if errors.Is(err, syswin.ERROR_NO_MORE_FILES) {
				return 0, errors.New("プロセス一覧に lsass.exe がいません")
			}
			return 0, fmt.Errorf("プロセス一覧の走査が途中で終わりました: %w", err)
		}
	}
}
