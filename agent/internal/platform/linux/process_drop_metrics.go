//go:build linux && ebpf

package linux

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// The eBPF process-monitor ring-buffer reader silently drops records in two
// cases: a record shorter than the expected struct size (a layout/size mismatch
// — the class of bug the stale-".o" args_len regression fell into, which silently
// discarded every record and was hard to diagnose precisely because it was
// silent), and a binary decode failure. These counters make that loss observable
// instead of invisible.
var (
	// procRecordsDiscarded counts ring-buffer records rejected for being shorter
	// than the expected packed struct size (needBytes).
	procRecordsDiscarded atomic.Uint64
	// procRecordsParseErr counts records that failed binary decoding.
	procRecordsParseErr atomic.Uint64
)

// dropSnapshot is a point-in-time read of the discard counters.
type dropSnapshot struct {
	discarded uint64
	parseErr  uint64
}

// grewSince reports whether either counter increased relative to prev — the
// signal that telemetry is being lost right now (as opposed to a stale non-zero
// total from an earlier blip). Kept pure so the reporting cadence is testable
// without spinning a goroutine or capturing log output.
func (s dropSnapshot) grewSince(prev dropSnapshot) bool {
	return s.discarded > prev.discarded || s.parseErr > prev.parseErr
}

// noiseSnapshot はノイズフィルタで意図的に落とした件数の点。
//
// 破棄カウンタ (dropSnapshot) が「落としてはいけないものを落とした」を表すのに
// 対し、こちらは「落として正しいものを落とした」を表す。混ぜると健全な抑制が
// 障害に見えるため、別の型・別のログ水準で扱う。
type noiseSnapshot struct {
	proc          uint64 // コンテナランタイムの足場 (isRuntimeNoiseProc)
	cred          uint64 // 良性の /proc 読み取り (isBenignCredTracer)
	hostIntegrity uint64 // 良性の capset (isBenignCapsetProc)
}

func (s noiseSnapshot) total() uint64 { return s.proc + s.cred + s.hostIntegrity }

// grewSince は前回から増えたかを返す。
func (s noiseSnapshot) grewSince(prev noiseSnapshot) bool {
	return s.proc > prev.proc || s.cred > prev.cred || s.hostIntegrity > prev.hostIntegrity
}

// currentNoiseSnapshot は 3 つのノイズカウンタをまとめて読む。
func currentNoiseSnapshot() noiseSnapshot {
	cred, hostIntegrity := preventionNoiseFiltered()
	return noiseSnapshot{
		proc:          procNoiseFiltered.Load(),
		cred:          cred,
		hostIntegrity: hostIntegrity,
	}
}

// reportProcessDropStats periodically checks the silent-discard counters and logs
// a WARN only when they grow, so a healthy agent stays quiet while any real
// telemetry loss surfaces immediately (with cumulative totals and the per-tick
// delta). Blocks until ctx is cancelled.
//
// あわせてノイズフィルタの累計も出す。3 つのカウンタ (procNoiseFiltered /
// credNoiseFiltered / hostIntegrityNoiseFiltered) はいずれも Add されるだけで
// 誰も読んでおらず、「どれだけ抑制できているか」を現場で確認する手段が無かった。
// 各カウンタの宣言コメントは "measurable rather than a silent, invisible drop"
// と書いているが、読み出しが無いままでは結局 invisible なままだった。
func reportProcessDropStats(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prev dropSnapshot
	var prevNoise noiseSnapshot
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := dropSnapshot{
				discarded: procRecordsDiscarded.Load(),
				parseErr:  procRecordsParseErr.Load(),
			}
			if cur.grewSince(prev) {
				slog.Warn("[process_monitor] eBPF プロセスイベントの破棄を検出しました（テレメトリ欠落の可能性）",
					"discarded_total", cur.discarded,
					"parse_errors_total", cur.parseErr,
					"discarded_delta", cur.discarded-prev.discarded,
					"parse_errors_delta", cur.parseErr-prev.parseErr,
				)
			}
			prev = cur

			// ノイズ抑制は正常動作なので INFO。増えたときだけ出すことで、
			// 静かなホストではログを汚さない。
			curNoise := currentNoiseSnapshot()
			if curNoise.grewSince(prevNoise) {
				slog.Info("[process_monitor] ノイズフィルタで抑制した件数",
					"total", curNoise.total(),
					"runtime_scaffold", curNoise.proc,
					"benign_cred_tracer", curNoise.cred,
					"benign_capset", curNoise.hostIntegrity,
					"delta", curNoise.total()-prevNoise.total(),
				)
			}
			prevNoise = curNoise
		}
	}
}
