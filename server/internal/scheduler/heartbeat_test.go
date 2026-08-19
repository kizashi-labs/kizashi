package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/edr-platform/server/internal/metrics"
)

// value reads a counter or gauge without pulling in client_golang's testutil
// package, which is not currently in this module's dependency graph.
func value(m prometheus.Metric) float64 {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return -1
	}
	if c := out.GetCounter(); c != nil {
		return c.GetValue()
	}
	return out.GetGauge().GetValue()
}

// trackRun itself: the record must be written, and written after the work.
//
// A counter incremented before fn would climb just as steadily for a worker
// that panics on every tick, which is the opposite of what it is for.

func TestTrackRunRecordsAfterTheWorkFinishes(t *testing.T) {
	const name = "test_worker_ordering"
	var ranBefore float64

	trackRun(context.Background(), name, func(context.Context) {
		ranBefore = value(metrics.SchedulerRuns.WithLabelValues(name))
	})

	if ranBefore != 0 {
		t.Errorf("処理の前に実行回数が %v になっています。落ちる処理でも数が増えます", ranBefore)
	}
	if got := value(metrics.SchedulerRuns.WithLabelValues(name)); got != 1 {
		t.Errorf("実行回数 = %v, want 1", got)
	}
}

func TestTrackRunMovesTheTimestampAndCountsEachTick(t *testing.T) {
	const name = "test_worker_counts"
	before := time.Now().Unix()

	for i := 1; i <= 3; i++ {
		trackRun(context.Background(), name, func(context.Context) {})
		if got := value(metrics.SchedulerRuns.WithLabelValues(name)); got != float64(i) {
			t.Fatalf("%d回目の実行後の回数 = %v, want %d", i, got, i)
		}
	}

	ts := value(metrics.SchedulerLastRunTimestamp.WithLabelValues(name))
	if ts < float64(before) {
		t.Errorf("最終実行時刻が更新されていません (%v < %v)。"+
			"回数だけでは、止まったワーカーは rate を見ないと分かりません", ts, before)
	}
}

// The context must reach the work. Passing the wrong one would make every
// worker outlive its shutdown.
func TestTrackRunPassesTheContextThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var got context.Context
	trackRun(ctx, "test_worker_ctx", func(c context.Context) { got = c })

	if got == nil {
		t.Fatal("処理が呼ばれていません")
	}
	if got.Err() == nil {
		t.Error("キャンセル済みの ctx が渡っていません。停止要求がワーカーに届きません")
	}
}
