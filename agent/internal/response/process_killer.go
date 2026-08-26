package response

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// ProcessKiller terminates processes by PID or name.
type ProcessKiller struct{}

// NewProcessKiller creates a new ProcessKiller.
func NewProcessKiller() *ProcessKiller {
	return &ProcessKiller{}
}

// KillByPID terminates a process by PID.
func (k *ProcessKiller) KillByPID(ctx context.Context, pid int) error {
	_ = ctx
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("failed to kill process %d: %w", pid, err)
	}
	return nil
}

// KillByName terminates all processes matching the given name (cross-platform).
func (k *ProcessKiller) KillByName(ctx context.Context, name string) ([]int, error) {
	pids, err := k.findPIDsByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return k.killPIDs(ctx, name, pids)
}

// killProcess is the actual kill, in a variable so the "found them and could
// not kill any" case is reachable from a test.
//
// **この差し替え口が無いと、その検査は権限に依存します。** 実際、最初に
// 書いた検査は PID 1 を使っていて、root で走るこの環境では skip され、
// **判定を消す変異を素通りさせました。** 走らない検査と、通った検査は、
// 要約行が同じです。
var killProcess = func(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// killPIDs stops each pid, and reports whether the attempt achieved anything.
//
// 探す処理と分けてあるのは、**「見つかったのに1つも殺せない」状況を
// テストから作れるようにするため**です。分けていないと、その状況を作るには
// 本物のプロセス発見に依存することになり、結局確かめられません。
func (k *ProcessKiller) killPIDs(ctx context.Context, name string, pids []int) ([]int, error) {
	_ = ctx

	// 殺せなかった PID を捨てないこと。
	//
	// 以前は killed だけを積んで err に nil を返していました。5件見つけて
	// 5件とも権限で失敗しても、戻り値は ([], nil) —— **「その名前のプロセスは
	// 動いていなかった」とまったく同じ**です。呼び出し側は成功として記録し、
	// コンソールには「対処済み」と出て、プロセスは動き続けます。
	//
	// 一部でも殺せたときは成功のままにします（部分的な対処は対処です）。
	// 見つけたのに1つも殺せなかったときだけ、失敗として返します。
	var killed []int
	var failed []int
	for _, pid := range pids {
		if err := killProcess(pid); err != nil {
			slog.Warn("プロセスを停止できませんでした", "pid", pid, "name", name, "error", err)
			failed = append(failed, pid)
			continue
		}
		killed = append(killed, pid)
	}
	if len(killed) == 0 && len(failed) > 0 {
		return nil, fmt.Errorf("%s に一致する %d 件のプロセスを1つも停止できませんでした",
			name, len(failed))
	}
	if len(failed) > 0 {
		slog.Warn("一部のプロセスを停止できませんでした",
			"name", name, "killed", len(killed), "failed", len(failed))
	}
	return killed, nil
}

// findPIDsByName finds all PIDs for processes with the given executable name.
func (k *ProcessKiller) findPIDsByName(ctx context.Context, name string) ([]int, error) {
	_ = ctx
	var pids []int

	// Try /proc (Linux)
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(comm)) == name {
				pids = append(pids, pid)
			}
		}
		return pids, nil
	}

	return pids, nil
}
