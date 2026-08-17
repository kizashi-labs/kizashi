package main

import (
	"context"
	"testing"
	"time"
)

// TestEventLossRate / TestReportEventLoss cover the ingest-shortfall gate.
//
// The soak printed "送信 N 件" and "着信 M 件" side by side from the start and
// never compared them, so telemetry could vanish between the simulated agents and
// the events table with nothing failing. Measured across six 2026-08-04 runs of
// the same manifest (seed 20260728): 0, 16, 34, 81, 328 and 405 events lost —
// 0% to 0.27%. A lost event is a missed detection that leaves no trace, and it
// also makes ATT&CK detection-rate results unreadable: a technique that did not
// alert could be a rule that failed or an event that never arrived.
func TestEventLossRate(t *testing.T) {
	cases := []struct {
		name          string
		sent, arrived int64
		want          float64
		tolerance     float64
	}{
		{name: "欠損なし", sent: 152186, arrived: 152186, want: 0},
		{name: "実測の最大 (405件)", sent: 152163, arrived: 151758, want: 0.2661, tolerance: 0.0005},
		{name: "実測の最小 (16件)", sent: 152164, arrived: 152148, want: 0.0105, tolerance: 0.0005},
		{name: "全損", sent: 100, arrived: 0, want: 100},
		// Leftover rows from an earlier run are a different problem; reporting a
		// negative loss rate would only obscure this one.
		{name: "着信が送信を上回る場合は0", sent: 100, arrived: 120, want: 0},
		{name: "送信0なら0", sent: 0, arrived: 0, want: 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := eventLossRate(tc.sent, tc.arrived)
			tol := tc.tolerance
			if tol == 0 {
				tol = 1e-9
			}
			if diff := got - tc.want; diff > tol || diff < -tol {
				t.Errorf("eventLossRate(%d, %d) = %.4f, 期待 %.4f", tc.sent, tc.arrived, got, tc.want)
			}
		})
	}
}

func TestReportEventLoss(t *testing.T) {
	cases := []struct {
		name          string
		sent, arrived int64
		maxPct        float64
		wantFail      bool
		why           string
	}{
		{
			name: "実測の範囲内は通す", sent: 152163, arrived: 151758, maxPct: 1,
			wantFail: false,
			why:      "0.27% は 2026-08-04 の実測最大。ここで落ちるとノイズで赤くなる",
		},
		{
			name: "上限を超えたら失敗する", sent: 100000, arrived: 97000, maxPct: 1,
			wantFail: true,
			why:      "3% の欠損は取り込み経路の退行。誰も見ていなければ検知漏れとして現れる",
		},
		{
			name: "上限ちょうどは通す", sent: 100000, arrived: 99000, maxPct: 1,
			wantFail: false,
		},
		{
			name: "欠損ゼロ", sent: 100, arrived: 100, maxPct: 1,
			wantFail: false,
		},
		{
			// The flag defaults to 0 so existing callers keep their behaviour; the
			// figure is still logged, which is the half that was missing before.
			name: "上限0なら判定しない", sent: 100000, arrived: 1, maxPct: 0,
			wantFail: false,
			why:      "既定は記録のみ。既存の呼び出しの挙動を変えない",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := reportEventLoss(tc.sent, tc.arrived,
				eventLossRate(tc.sent, tc.arrived), tc.maxPct)
			if got != tc.wantFail {
				t.Errorf("reportEventLoss(送信=%d, 着信=%d, 上限=%.1f%%) = %v, 期待 %v\n%s",
					tc.sent, tc.arrived, tc.maxPct, got, tc.wantFail, tc.why)
			}
		})
	}
}

// TestSettleEventCountDisabled pins the default: with no settle period the count
// is returned untouched, so existing callers keep their behaviour and the flag
// stays purely additive.
//
// The settle path itself needs a database, so the soak job exercises it rather
// than this test; what matters here is that omitting the flag cannot change the
// number. A diagnostic that silently altered the measurement it was added to
// explain would be worse than no diagnostic.
func TestSettleEventCountDisabled(t *testing.T) {
	for _, seconds := range []int{0, -1} {
		settle := time.Duration(seconds) * time.Second
		got := settleEventCount(context.Background(), nil, nil, window{}, 152022, settle)
		if got != 152022 {
			t.Errorf("settle=%s で件数が %d に変わりました（期待 152022）", settle, got)
		}
	}
}
