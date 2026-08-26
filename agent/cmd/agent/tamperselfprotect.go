package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/integrity"
	"github.com/edr-platform/agent/internal/tamper"
)

// runTamperSelfProtect delivers the self-protection findings that need no kernel
// support, and is therefore the only tamper path that runs in shipping builds.
//
// The kernel paths (runTamperService — Linux eBPF LSM task_kill, the Windows
// prevention driver) can actually *deny* a kill, but they sit behind the
// `prevention` build tag and are not in the binaries CI publishes. Everything
// here is observation only: it cannot stop an administrator from killing the
// agent, but it makes sure the attempt is not silent, which is the part that was
// missing entirely.
//
// Three sources feed it:
//
//   - The watchdog's spool, holding deaths observed while no agent was running to
//     report them.
//   - Periodic integrity checks of the agent binary and config against an
//     in-memory baseline.
//   - Liveness of the supervising watchdog.
//
// startupErr carries the result of the start-up integrity check, which runs
// before the transport exists and so cannot report itself.
//
// Blocks until ctx is cancelled.
func runTamperSelfProtect(ctx context.Context, sender collector.EventSender, agentID, configPath string, startupErr error) {
	dataDir := filepath.Dir(configPath)
	send := tamperSender(ctx, sender, agentID, dataDir)

	reportStartupIntegrity(send, startupErr)
	drainTamperSpool(dataDir, send)

	mon := tamper.NewMonitor(send)
	if exe, err := os.Executable(); err == nil {
		mon.WatchBinary(exe)
	} else {
		slog.Warn("[tamper] 自身の実行ファイルパスを解決できず、バイナリ改ざんを監視できません", "error", err)
	}
	mon.WatchConfig(configPath)
	mon.WatchWatchdog(tamper.WatchdogPIDFromEnv())
	mon.Run(ctx)
}

// tamperSender returns a reporter that ships one finding to the server.
//
// GRPCClient.SendEvents already falls back to the offline ring buffer when the
// stream is down, so a disconnected agent does not lose findings and this does
// not need its own retry. An error here means even that buffering failed, and the
// finding goes back to the watchdog spool so the next start can try again —
// losing the record of an attempt to disable the agent is the one outcome worth
// extra code to avoid.
func tamperSender(ctx context.Context, sender collector.EventSender, agentID, dataDir string) func(tamper.Payload) {
	return func(p tamper.Payload) {
		batch := collector.BuildTamperEvent(agentID, p)
		if batch == nil {
			return // BuildTamperEvent already logged the serialise failure
		}
		if err := sender.SendEvents(ctx, batch); err != nil {
			slog.Warn("[tamper] 改ざん所見の送信に失敗しました。スプールへ退避します",
				"type", p.TamperType, "error", err)
			if err := tamper.Append(dataDir, p); err != nil {
				slog.Error("[tamper] スプールへの退避にも失敗しました。この所見は失われます",
					"type", p.TamperType, "error", err)
			}
			return
		}
		slog.Warn("[tamper] 改ざんの疑いを検知しサーバへ報告しました",
			"type", p.TamperType,
			"component", p.Component,
			"reason", p.Reason,
		)
	}
}

// reportStartupIntegrity turns a failed start-up integrity check into a finding.
//
// Only a hash mismatch is reported as tampering. The check's other failure modes
// — the executable path cannot be resolved, the stored hash cannot be read — mean
// the check could not run, not that it failed. Reporting those as "the binary was
// modified" would put an unfalsifiable alert in front of an analyst, and the
// second time it happened they would learn to ignore the rule.
func reportStartupIntegrity(send func(tamper.Payload), err error) {
	if err == nil {
		return
	}
	if !errors.Is(err, integrity.ErrTampered) {
		slog.Warn("[tamper] 起動時の整合性チェックを実行できませんでした（改ざんの有無は判定不能）", "error", err)
		return
	}
	exe, exeErr := os.Executable()
	if exeErr != nil {
		exe = ""
	}
	send(tamper.New(tamper.TypeBinaryModified, tamper.ComponentBinary, false).
		WithPath(exe).
		WithReason("起動時の整合性チェックで、保存されたハッシュとエージェントバイナリが一致しませんでした"))
}

// drainTamperSpool ships whatever the watchdog recorded while the agent was down.
func drainTamperSpool(dataDir string, send func(tamper.Payload)) {
	found, skipped, err := tamper.Drain(dataDir)
	if err != nil {
		slog.Warn("[tamper] スプールの取り出しに失敗しました", "error", err)
	}
	if skipped > 0 {
		// Surfaced rather than swallowed: a spool full of unparseable lines looks
		// exactly like a spool with nothing in it, and the two mean opposite things.
		slog.Warn("[tamper] スプールに解釈できない行がありました", "skipped", skipped)
	}
	for _, p := range found {
		send(p)
	}
	if len(found) > 0 {
		slog.Info("[tamper] ウォッチドッグが記録した所見を送信しました", "count", len(found))
	}
}
