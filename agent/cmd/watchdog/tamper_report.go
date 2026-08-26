package main

import (
	"log/slog"
	"path/filepath"
	"runtime"

	"github.com/edr-platform/agent/internal/tamper"
)

// recordAgentDeath spools a tamper finding for an agent exit the watchdog did not
// ask for.
//
// The watchdog cannot report this itself — it has no gRPC client, and the process
// that owns the connection is the one that just died. It writes to the spool in
// the config directory and the agent drains it on its next start, which is a few
// seconds later thanks to the restart backoff.
//
// Enforced is always false here: the watchdog observes and restarts, it does not
// deny. Denying a kill needs the kernel layer (Linux eBPF LSM task_kill / the
// Windows prevention driver), which is behind the `prevention` build tag and is
// not in shipping builds.
func recordAgentDeath(configFile string, agentPID, exitCode int, waitErr error) {
	dataDir := filepath.Dir(configFile)

	sig, signalled := classifyExit(waitErr)

	// The type carries the distinction, not a field: see TypeAgentExited on why
	// this must not depend on Sigma matching a signal number.
	tamperType := tamper.TypeAgentExited
	if signalled {
		tamperType = tamper.TypeAgentKilled
	}

	p := tamper.New(tamperType, tamper.ComponentAgent, false).
		WithTarget(agentPID).
		WithExitCode(exitCode)

	switch {
	case signalled:
		p = p.WithSignal(sig).
			WithReason("エージェントプロセスがシグナルで終了しました")
	case runtime.GOOS == "windows":
		// See exitreason_windows.go: the exit code cannot separate kill from crash.
		// Say so in the finding rather than letting the reader assume either.
		p = p.WithReason("エージェントプロセスが予期せず終了しました（Windows では終了コードから強制終了とクラッシュを区別できません）")
	default:
		p = p.WithReason("エージェントプロセスが予期せず終了しました（シグナルによらない終了）")
	}

	if err := tamper.Append(dataDir, p); err != nil {
		slog.Warn("改ざん所見のスプール書き込みに失敗しました", "error", err)
		return
	}
	slog.Warn("エージェントの予期しない終了を改ざん所見として記録しました",
		"agent_pid", agentPID,
		"exit_code", exitCode,
		"signal", sig,
		"spool", filepath.Join(dataDir, tamper.SpoolFileName),
	)
}
