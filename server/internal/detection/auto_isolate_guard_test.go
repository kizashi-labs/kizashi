package detection

import (
	"testing"
	"time"
)

// 時間に依存する判定なので、時計を固定して検証する。実時間に依存させると
// 「たまたま通る」テストになり、境界の誤りを検出できない。
func fixedGuard(cooldown time.Duration, budget int) (*isolationGuard, *time.Time) {
	g := newIsolationGuard(cooldown, budget, false)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	return g, &now
}

// 周期的な誤検知は同じ端末で繰り返し鳴る。1 度目は止められないが、2 度目以降を
// 抑えなければ「解除しても数分で再隔離される」状態になる。実際にそれが起きていた。
func TestGuardBlocksRepeatIsolationOfSameAgent(t *testing.T) {
	g, now := fixedGuard(30*time.Minute, 10)

	if v := g.allow("agent-1"); !v.allow {
		t.Fatalf("1 回目が拒否されました: %s", v.reason)
	}
	if v := g.allow("agent-1"); v.allow {
		t.Error("冷却期間中の 2 回目が許可されました")
	}

	// 別の端末は影響を受けない
	if v := g.allow("agent-2"); !v.allow {
		t.Errorf("別端末が巻き添えで拒否されました: %s", v.reason)
	}

	// 冷却期間を過ぎれば再び許可される
	*now = now.Add(31 * time.Minute)
	if v := g.allow("agent-1"); !v.allow {
		t.Errorf("冷却期間経過後に拒否されました: %s", v.reason)
	}
}

// 誤検知が広範囲に及んだとき、業務停止の規模を頭打ちにする。上限に当たるのは
// 人が介入すべき事象なので、黙って全台止めるより止まるほうがよい。
func TestGuardEnforcesHourlyBudget(t *testing.T) {
	g, now := fixedGuard(time.Nanosecond, 3) // 冷却は無効化して上限だけを見る

	for i, id := range []string{"a", "b", "c"} {
		*now = now.Add(time.Minute)
		if v := g.allow(id); !v.allow {
			t.Fatalf("%d 台目が拒否されました: %s", i+1, v.reason)
		}
	}
	*now = now.Add(time.Minute)
	if v := g.allow("d"); v.allow {
		t.Error("上限を超えて 4 台目が許可されました")
	}

	// 窓から外れれば回復する
	*now = now.Add(61 * time.Minute)
	if v := g.allow("e"); !v.allow {
		t.Errorf("窓の経過後も拒否されました: %s", v.reason)
	}
}

// 既定値は「設定を書かなくても安全側」でなければ意味がない。
func TestGuardDefaultsAreSafe(t *testing.T) {
	g := newIsolationGuard(0, 0, false)
	if g.cooldown != defaultIsolationCooldown {
		t.Errorf("既定の冷却期間 = %v, want %v", g.cooldown, defaultIsolationCooldown)
	}
	if g.budget != defaultIsolationBudget {
		t.Errorf("既定の上限 = %d, want %d", g.budget, defaultIsolationBudget)
	}
	if g.budget <= 0 {
		t.Error("上限が 0 以下だと全台隔離を止められません")
	}
}

// ドライランは「何が止まるはずだったか」を先に見るための状態。
// allow まで拒否してしまうと、抑止と区別がつかなくなる。
func TestGuardDryRunStillAllowsDecision(t *testing.T) {
	g := newIsolationGuard(time.Minute, 3, true)
	if !g.isDryRun() {
		t.Fatal("ドライランが有効になっていません")
	}
	if v := g.allow("agent-1"); !v.allow {
		t.Errorf("ドライランで判定自体が拒否されました: %s", v.reason)
	}
}
