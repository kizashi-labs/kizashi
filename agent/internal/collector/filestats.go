// filestats.go — ファイルイベントの action 別カウンタ。
//
// なぜ必要か。検証EC2 の実測で、Linux エージェントは 7 日間に file イベントの
// DELETE を 0 件・RENAME を 0 件しか出していない（同期間 Windows は DELETE 32,191 /
// RENAME 2,500）。ところがコードを読む限り欠落する理由が無い——inotify の watchMask は
// IN_DELETE / IN_MOVED_FROM / IN_MOVED_TO を含み、inotifyMaskToAction は "delete" /
// "rename" を返し、fileAction() は proto enum に対応しており、EmitFile は action で
// 選別しない。実装は初回コミットから揃っている。
//
// つまり「センサーが拾っていない」のか「拾ったあとどこかで落ちている」のかが、
// 外形（DB とストリーム）からは区別できない。9 つの仮説を外形試験で潰したが決着せず、
// 推測を続けるより境界にカウンタを置くほうが早い、というのがこの計装の動機である。
// 詳細は docs/死蔵経路の全数棚卸し_20260810.md §12-13。
//
// センサーが生成した瞬間（EmitFile の入口）で数えるので、
//
//	generated が 0        → inotify/ETW がそもそもそのイベントを拾っていない
//	generated > 0 かつ DB 0 → 生成後、送信・取込・保存のどこかで落ちている
//
// のどちらかに必ず切り分かる。
package collector

import (
	"sort"
	"sync"
	"sync/atomic"
)

// FileEmitStat is the per-action tally at the sensor boundary.
type FileEmitStat struct {
	// Generated is every event the sensor produced, delivered or not.
	Generated uint64
	// Dropped is the subset the send queue could not accept. Generated minus
	// Dropped is what actually entered the pipeline.
	Dropped uint64
}

var (
	fileEmitMu    sync.RWMutex
	fileEmitStats = map[string]*fileEmitCounters{}
)

type fileEmitCounters struct {
	generated atomic.Uint64
	dropped   atomic.Uint64
}

// countersFor returns the counter pair for an action, creating it on first use.
// The action set is small and bounded by inotifyMaskToAction / the Windows and
// macOS equivalents, so the map cannot grow without bound.
func countersFor(action string) *fileEmitCounters {
	if action == "" {
		action = "unknown"
	}
	fileEmitMu.RLock()
	c := fileEmitStats[action]
	fileEmitMu.RUnlock()
	if c != nil {
		return c
	}
	fileEmitMu.Lock()
	defer fileEmitMu.Unlock()
	if c = fileEmitStats[action]; c == nil {
		c = &fileEmitCounters{}
		fileEmitStats[action] = c
	}
	return c
}

// FileEmitSnapshot returns a copy of the per-action tallies, sorted by action so
// the /metrics output is stable between scrapes.
func FileEmitSnapshot() map[string]FileEmitStat {
	fileEmitMu.RLock()
	defer fileEmitMu.RUnlock()
	out := make(map[string]FileEmitStat, len(fileEmitStats))
	for action, c := range fileEmitStats {
		out[action] = FileEmitStat{Generated: c.generated.Load(), Dropped: c.dropped.Load()}
	}
	return out
}

// FileEmitActions returns the observed action names in sorted order.
func FileEmitActions() []string {
	fileEmitMu.RLock()
	actions := make([]string, 0, len(fileEmitStats))
	for a := range fileEmitStats {
		actions = append(actions, a)
	}
	fileEmitMu.RUnlock()
	sort.Strings(actions)
	return actions
}
