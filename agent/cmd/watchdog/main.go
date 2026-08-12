// EDR Agent Watchdog
//
// Runs the EDR agent as a supervised subprocess and automatically restarts it
// if it exits unexpectedly. This is the entry point for OS service managers
// (systemd, Windows Service, launchd) — the watchdog is what gets registered,
// and it in turn manages the agent lifecycle.
//
// Usage: edr-watchdog --agent /usr/local/bin/edr-agent --config /etc/edr/agent.toml
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/edr-platform/agent/internal/tamper"
)

const (
	minRestartDelay = 2 * time.Second
	maxRestartDelay = 5 * time.Minute
	// Reset backoff after the process runs for this long without crashing
	stableThreshold = 30 * time.Second
	// If an updated binary crashes within this window, roll back to the backup
	updateStableThreshold = 60 * time.Second
)

func main() {
	agentBin := flag.String("agent", defaultAgentBin(), "path to edr-agent binary")
	configFile := flag.String("config", defaultConfigFile(), "path to agent config file")
	pidFile := flag.String("pidfile", defaultPIDFile(), "watchdog PID file")
	maxCrashes := flag.Int("max-crashes", 0, "max consecutive crashes before giving up (0 = unlimited)")
	flag.Parse()

	// Write PID file
	if err := writePID(*pidFile); err != nil {
		slog.Warn("PIDファイルの書き込みに失敗しました", "path", *pidFile, "error", err)
	}
	defer os.Remove(*pidFile)

	slog.Info("EDRエージェント ウォッチドッグを起動しました",
		"agent", *agentBin,
		"config", *configFile,
		"pid", os.Getpid(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle termination signals: propagate to child then exit cleanly
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("シャットダウンシグナルを受信しました", "signal", sig)
		cancel()
	}()

	runSupervisor(ctx, *agentBin, *configFile, *maxCrashes)
	slog.Info("ウォッチドッグを終了します")
}

// updateMarker is the JSON structure written by the updater into {dataDir}/.update-pending.
type updateMarker struct {
	NewBinary string `json:"new_binary"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// backupBinPath returns the path that should be used for the pre-update backup of agentBin.
func backupBinPath(agentBin string) string {
	if runtime.GOOS == "windows" {
		return agentBin[:len(agentBin)-len(filepath.Ext(agentBin))] + ".bak.exe"
	}
	return agentBin + ".bak"
}

// checkAndApplyUpdate reads {dataDir}/.update-pending, backs up the current binary,
// moves the new binary into place, and removes the marker file.
// It returns updated=true when a swap was performed.
func checkAndApplyUpdate(agentBin string) (updated bool, err error) {
	dataDir := filepath.Dir(agentBin)
	markerPath := filepath.Join(dataDir, ".update-pending")

	data, err := os.ReadFile(markerPath)
	if os.IsNotExist(err) {
		return false, nil // no pending update — normal path
	}
	if err != nil {
		return false, fmt.Errorf("アップデートマーカーの読み込みに失敗しました: %w", err)
	}

	var marker updateMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return false, fmt.Errorf("アップデートマーカーのパースに失敗しました: %w", err)
	}

	newBin := marker.NewBinary
	if newBin == "" {
		newBin = filepath.Join(dataDir, "edr-agent.new")
	}

	if _, err := os.Stat(newBin); err != nil {
		return false, fmt.Errorf("新しいバイナリが見つかりません (%s): %w", newBin, err)
	}

	bakBin := backupBinPath(agentBin)

	slog.Info("アップデートを適用します",
		"version", marker.Version,
		"new_binary", newBin,
		"backup", bakBin,
	)

	// 1. Back up the current binary.
	if err := os.Rename(agentBin, bakBin); err != nil {
		return false, fmt.Errorf("現在のバイナリのバックアップに失敗しました: %w", err)
	}

	// 2. Move the new binary into place.
	if err := os.Rename(newBin, agentBin); err != nil {
		// Attempt to restore the backup so the agent isn't left missing.
		if restoreErr := os.Rename(bakBin, agentBin); restoreErr != nil {
			slog.Error("バイナリの復元に失敗しました — 手動での対応が必要です",
				"backup", bakBin, "error", restoreErr)
		}
		return false, fmt.Errorf("新しいバイナリの移動に失敗しました: %w", err)
	}

	// 3. Remove the marker so we don't attempt the swap again on the next restart.
	if err := os.Remove(markerPath); err != nil {
		slog.Warn("アップデートマーカーの削除に失敗しました", "path", markerPath, "error", err)
	}

	slog.Info("バイナリのスワップが完了しました", "version", marker.Version)
	return true, nil
}

// rollbackUpdate restores the backup binary, replacing the (presumably broken) current one.
func rollbackUpdate(agentBin string) {
	bakBin := backupBinPath(agentBin)
	slog.Warn("アップデート後にクラッシュを検出しました — バックアップから復元します",
		"backup", bakBin, "agent", agentBin)

	// Remove the broken new binary first (best-effort).
	_ = os.Remove(agentBin)

	if err := os.Rename(bakBin, agentBin); err != nil {
		slog.Error("ロールバックに失敗しました — 手動での対応が必要です",
			"backup", bakBin, "agent", agentBin, "error", err)
		return
	}
	slog.Info("ロールバックが完了しました。前のバージョンに戻りました")
}

// runSupervisor is the main supervision loop.
func runSupervisor(ctx context.Context, agentBin, configFile string, maxCrashes int) {
	delay := minRestartDelay
	crashes := 0
	// wasUpdateRun is true when the immediately preceding agent launch followed a
	// binary swap, so that a quick crash triggers rollback rather than plain backoff.
	wasUpdateRun := false

	for {
		if ctx.Err() != nil {
			return
		}

		if maxCrashes > 0 && crashes >= maxCrashes {
			slog.Error("最大クラッシュ回数に達しました。ウォッチドッグを停止します",
				"crashes", crashes, "max", maxCrashes)
			return
		}

		// Check for a pending update and swap binaries before starting the agent.
		updated, updateErr := checkAndApplyUpdate(agentBin)
		if updateErr != nil {
			slog.Warn("アップデートの適用中にエラーが発生しました。現在のバイナリで続行します", "error", updateErr)
		}
		wasUpdateRun = updated

		startedAt := time.Now()
		agentPID, exitCode, err := runAgent(ctx, agentBin, configFile)

		// Context cancelled = intentional shutdown
		if ctx.Err() != nil {
			return
		}

		runDuration := time.Since(startedAt)

		if err != nil {
			slog.Warn("エージェントプロセスが異常終了しました",
				"error", err,
				"exit_code", exitCode,
				"run_duration", runDuration.Round(time.Second),
			)
		} else {
			slog.Warn("エージェントプロセスが予期せず終了しました",
				"exit_code", exitCode,
				"run_duration", runDuration.Round(time.Second),
			)
		}

		// If the agent crashed quickly after an update swap, roll back to the
		// previous binary so the next iteration starts with the known-good version.
		rolledBack := wasUpdateRun && runDuration < updateStableThreshold
		if rolledBack {
			rollbackUpdate(agentBin)
		}
		wasUpdateRun = false // rollback (or stability) resets the flag

		// Report the death as a tamper finding — the agent does not stop on its
		// own, so an exit the watchdog did not ask for is either an attack or a
		// crash, and both are things a SOC needs to see.
		//
		// Two exclusions keep the signal honest:
		//   - A post-update rollback is our own doing, not tampering.
		//   - In a crash loop every iteration would spool an identical finding and
		//     the spool cap would evict the first one, which is the only one that
		//     explains how the loop started. So report the first death and any
		//     death that follows a stable run, and stay quiet in between.
		if !rolledBack && (crashes == 0 || runDuration >= stableThreshold) {
			recordAgentDeath(configFile, agentPID, exitCode, err)
		}

		crashes++

		// Reset backoff if the process ran stably for a while
		if runDuration >= stableThreshold {
			delay = minRestartDelay
			crashes = 1
			slog.Info("プロセスは安定して実行されていたためバックオフをリセットします")
		}

		slog.Info("エージェントを再起動します",
			"delay", delay,
			"attempt", crashes,
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		// Exponential backoff, capped at maxRestartDelay
		delay *= 2
		if delay > maxRestartDelay {
			delay = maxRestartDelay
		}
	}
}

// runAgent starts the agent subprocess and waits for it to exit.
// Returns (agent PID, exit code, error). error is nil for clean exits (even
// non-zero). The PID is reported so an unexpected death can be attributed to a
// concrete process in the tamper finding; it is 0 when the process never started.
func runAgent(ctx context.Context, agentBin, configFile string) (int, int, error) {
	args := []string{"--config", configFile}

	cmd := exec.CommandContext(ctx, agentBin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	// Hand our PID to the agent so it can notice the supervisor disappearing.
	// Killing the watchdog first is what makes killing the agent stick, and the
	// agent is the only one of the pair still alive to report it.
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", tamper.WatchdogPIDEnv, os.Getpid()))

	// On Unix: put child in its own process group so signals
	// don't automatically propagate from terminal to child —
	// we want to control shutdown ourselves.
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return 0, -1, fmt.Errorf("エージェントの起動に失敗しました: %w", err)
	}

	pid := cmd.Process.Pid
	slog.Info("エージェントプロセスを起動しました", "pid", pid)
	writeChildPID(pid)

	// Wait for context cancellation or process exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Graceful shutdown: send SIGTERM to child and wait up to 15s
		slog.Info("エージェントに終了シグナルを送信します", "pid", pid)
		gracefulStop(cmd)
		select {
		case err := <-done:
			return pid, exitCode(err), nil
		case <-time.After(15 * time.Second):
			slog.Warn("エージェントが応答しないため強制終了します")
			cmd.Process.Kill()
			<-done
			return pid, -1, nil
		}

	case err := <-done:
		return pid, exitCode(err), err
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func writeChildPID(pid int) {
	dir := filepath.Dir(defaultPIDFile())
	path := filepath.Join(dir, "edr-agent.pid")
	_ = os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644)
}

// ─── Platform defaults ────────────────────────────────────────

func defaultAgentBin() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\EDRAgent\edr-agent.exe`
	}
	return "/usr/local/bin/edr-agent"
}

func defaultConfigFile() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\EDRAgent\agent.toml`
	}
	return "/etc/edr/agent.toml"
}

func defaultPIDFile() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\EDRAgent\edr-watchdog.pid`
	}
	return "/var/run/edr-watchdog.pid"
}
