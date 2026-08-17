package isolation

import (
	"log/slog"
	"sync"
	"time"
)

// 自動隔離の安全弁。
//
// 隔離の判定は「AutoIsolate かつ severity >= 閾値」の一段しかなかった。severity は
// 検知器が自分で決める値なので、誤検知が severity 10 を出せばそのまま端末が
// 止まる。実際に procThreat が 6 時間周期で severity 10 + AutoIsolate の誤検知を
// 出し続けており、AUTO_RESPONSE_ENABLED=false だけがそれを止めていた。
// つまり「安全なのは自動対応を丸ごと切っているから」という状態だった。
//
// ここでは判定の質ではなく被害の大きさを抑える。誤検知は無くならない前提で、
//
//   - 1 台を繰り返し止めない（同じ端末への連続隔離を冷却期間で抑える）
//   - 全社を止めない（時間あたりの隔離台数に上限を設ける）
//   - いきなり本番に効かせない（ドライランで「何が止まるはずだったか」を先に見る）
//
// を機械的に保証する。誤検知源そのものの修正は別の作業。
//
// このファイルは detection パッケージから移設した。安全弁が detection の中に
// あったせいで、detection を経由しない隔離経路（修復エンジン・プレイブック・
// 手動隔離・隔離アクション API）はどれも通らなかった。Guard は Gatekeeper の
// 一部であり、Gatekeeper 以外から呼ぶものではない。

const (
	// DefaultCooldown は同じ端末を再び自動隔離するまでの最短間隔。
	// 周期的な誤検知は同じ端末で繰り返し鳴る。1 度目は止められないが、
	// 2 度目以降を抑えれば「解除しても数分で再隔離される」状態は避けられる。
	DefaultCooldown = 30 * time.Minute

	// DefaultHourlyBudget は 1 時間あたりに自動隔離を許す台数。
	// 誤検知が広範囲に及んだとき、業務停止の規模をここで頭打ちにする。
	// 本物の攻撃が同時に多数の端末へ及ぶ場合は上限に当たるが、そのときは
	// 人が介入すべき事象なので、黙って全台止めるより通知して止まるほうがよい。
	DefaultHourlyBudget = 3

	budgetWindow = time.Hour
)

// guard decides whether an unattended isolation may proceed.
//
// 状態はプロセス内にしか無い。server-api と server-detect は別プロセスなので、
// 時間あたり上限はプロセスごとに独立して効く（2 プロセスなら実効上限は 2 倍）。
// 冷却期間も同様。詳細と対処方針は docs/debt/P5.md の P5-36 を参照。
type guard struct {
	mu sync.Mutex

	cooldown time.Duration
	budget   int
	window   time.Duration
	dryRun   bool

	lastByAgent map[string]time.Time
	recent      []time.Time

	// now is injectable for tests. 時間に依存する判定はテストで固定できないと
	// 検証できない。
	now func() time.Time
}

func newGuard(cooldown time.Duration, budget int, dryRun bool) *guard {
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	if budget <= 0 {
		budget = DefaultHourlyBudget
	}
	return &guard{
		cooldown:    cooldown,
		budget:      budget,
		window:      budgetWindow,
		dryRun:      dryRun,
		lastByAgent: make(map[string]time.Time),
		now:         time.Now,
	}
}

// verdict is why an unattended isolation was allowed or refused.
type verdict struct {
	allow  bool
	reason string
}

// allow reports whether agentID may be isolated now, and records the
// decision when it is allowed.
//
// 呼び出し側は allow が false でも黙ってはいけない。抑止したこと自体が
// 「誤検知が続いている」か「本物の広範囲攻撃が起きている」かの手がかりになる。
func (g *guard) allow(agentID string) verdict {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()

	if last, ok := g.lastByAgent[agentID]; ok {
		if elapsed := now.Sub(last); elapsed < g.cooldown {
			return verdict{false, "同じ端末を " +
				g.cooldown.String() + " 以内に再度隔離しようとしました（冷却期間中）"}
		}
	}

	// 窓から外れた記録を落としてから数える
	cutoff := now.Add(-g.window)
	kept := g.recent[:0]
	for _, t := range g.recent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.recent = kept

	if len(g.recent) >= g.budget {
		return verdict{false, "直近 " + g.window.String() +
			" の自動隔離が上限に達しました（サーキットブレーカー作動）"}
	}

	g.lastByAgent[agentID] = now
	g.recent = append(g.recent, now)
	return verdict{true, ""}
}

// isDryRun reports whether isolation should be recorded instead of executed.
func (g *guard) isDryRun() bool { return g.dryRun }

// logRefusal records a refused isolation. 抑止は沈黙させない。
func (g *guard) logRefusal(agentID, label string, origin Origin, reason string) {
	slog.Warn("自動隔離を抑止しました",
		"agent", agentID, "rule", label, "経路", string(origin), "理由", reason)
}
