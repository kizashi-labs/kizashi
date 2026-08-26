package main

// ローカルアラート経路のテスト。
//
// 押さえたいのは 3 点:
//   1. 閾値を超えたスコアだけが即時送信を要求すること (超えないものは要求しない)
//   2. 連続した閾値超えが 1 件ごとの送信にならないこと (間引き)
//   3. 間引きの基準が「最後に送った時刻」であること — 拒否のたびに時計を
//      進めてしまうと、閾値超えが続く間ずっと送信できなくなる

import (
	"testing"
	"time"

	"github.com/edr-platform/agent/internal/scanner"
)

func alertScore() scanner.AnomalyScore {
	return scanner.AnomalyScore{Score: 0.9, Reasons: []string{"test"}, LocalAlert: true}
}

func quietScore() scanner.AnomalyScore {
	return scanner.AnomalyScore{Score: 0.4, Reasons: []string{"test"}}
}

// TestNoteAnomaly_BelowThresholdDoesNotFlush は閾値未満で即時送信を
// 要求しないこと。ここが緩むと全イベントが即時送信になりバッチが無意味になる。
func TestNoteAnomaly_BelowThresholdDoesNotFlush(t *testing.T) {
	gate := newLocalAlertGate(time.Second)
	now := time.Unix(1000, 0)

	if noteAnomaly(gate, now, "process", quietScore()) {
		t.Error("閾値未満で即時送信が要求された")
	}
	// スコア 0 (何の兆候も無い) も同様。
	if noteAnomaly(gate, now, "process", scanner.AnomalyScore{}) {
		t.Error("スコア 0 で即時送信が要求された")
	}
}

// TestNoteAnomaly_AboveThresholdFlushes は閾値超えで即時送信を要求すること。
func TestNoteAnomaly_AboveThresholdFlushes(t *testing.T) {
	gate := newLocalAlertGate(time.Second)
	if !noteAnomaly(gate, time.Unix(1000, 0), "process", alertScore()) {
		t.Error("閾値超えなのに即時送信が要求されなかった")
	}
}

// TestNoteAnomaly_ThrottlesBurst はバースト時に 1 件ごとの送信にならないこと。
// 攻撃中は閾値超えが連続するため、ここが効かないと 1 イベントだけの RPC が
// 並んでスループットが落ちる。
func TestNoteAnomaly_ThrottlesBurst(t *testing.T) {
	gate := newLocalAlertGate(time.Second)
	base := time.Unix(1000, 0)

	allowed := 0
	for i := 0; i < 10; i++ {
		// 10 件が 100ms 間隔で来る = 全体で 900ms、最小間隔 1s に収まる
		if noteAnomaly(gate, base.Add(time.Duration(i)*100*time.Millisecond), "process", alertScore()) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("即時送信の回数 = %d, want 1 (間引かれていない)", allowed)
	}
}

// TestNoteAnomaly_AllowsAgainAfterGap は最小間隔を過ぎれば再び送れること。
// 間引きが「一度きり」になってしまうと 2 回目以降の攻撃を取りこぼす。
func TestNoteAnomaly_AllowsAgainAfterGap(t *testing.T) {
	gate := newLocalAlertGate(time.Second)
	base := time.Unix(1000, 0)

	if !noteAnomaly(gate, base, "process", alertScore()) {
		t.Fatal("1 回目が許可されなかった")
	}
	if noteAnomaly(gate, base.Add(999*time.Millisecond), "process", alertScore()) {
		t.Error("最小間隔内なのに許可された")
	}
	if !noteAnomaly(gate, base.Add(time.Second), "process", alertScore()) {
		t.Error("最小間隔を過ぎたのに許可されなかった")
	}
}

// TestLocalAlertGate_RejectionDoesNotResetClock は拒否が時計を進めないこと。
//
// 拒否のたびに last を更新すると、閾値超えが最小間隔より短い周期で続く限り
// 永久に送信できなくなる (まさに攻撃中に黙る)。
func TestLocalAlertGate_RejectionDoesNotResetClock(t *testing.T) {
	gate := newLocalAlertGate(time.Second)
	base := time.Unix(1000, 0)

	if !gate.allow(base) {
		t.Fatal("1 回目が許可されなかった")
	}
	// 100ms ごとに叩き続ける。1s 経過時点で許可されなければならない。
	for ms := 100; ms < 1000; ms += 100 {
		if gate.allow(base.Add(time.Duration(ms) * time.Millisecond)) {
			t.Fatalf("%dms 時点で許可された (最小間隔 1s)", ms)
		}
	}
	if !gate.allow(base.Add(time.Second)) {
		t.Error("叩き続けた結果 1s 経過後も許可されない (拒否が時計を進めている)")
	}
}

// TestLocalAlertGate_FirstCallAlwaysAllowed は初回が必ず通ること。
// ゼロ値の last を「直前に送った」と誤解すると、起動直後の最初の
// アラートが取りこぼされる。
func TestLocalAlertGate_FirstCallAlwaysAllowed(t *testing.T) {
	if !newLocalAlertGate(time.Hour).allow(time.Unix(0, 0)) {
		t.Error("初回が許可されなかった")
	}
}
