package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/metrics"
)

// 回っていることと、仕事ができていることは別の事実です。
//
// SchedulerRuns は tick が何をしたかに関係なく増えます。最初のクエリで
// 失敗して戻ったワーカーも、40枚の証明書を更新したワーカーも、同じ形で
// 増えます。毎回失敗しているワーカーの回数は、健全なワーカーとまったく
// 同じ速さで climb します。

func TestATickThatGaveUpDoesNotLookLikeASuccessfulOne(t *testing.T) {
	const name = "test_worker_gave_up"
	before := value(metrics.SchedulerLastSuccessTimestamp.WithLabelValues(name))

	trackRun(context.Background(), name, func(ctx context.Context) {
		fail(ctx, errors.New("読めませんでした"), "テスト: 読み取りに失敗")
	})

	if got := value(metrics.SchedulerRuns.WithLabelValues(name)); got != 1 {
		t.Errorf("実行回数 = %v, want 1（失敗しても「回った」のは事実です）", got)
	}
	if got := value(metrics.SchedulerFailures.WithLabelValues(name)); got != 1 {
		t.Errorf("失敗回数 = %v, want 1", got)
	}
	if after := value(metrics.SchedulerLastSuccessTimestamp.WithLabelValues(name)); after != before {
		t.Errorf("諦めた回で最終成功時刻が動きました (%v → %v)。"+
			"「回っているが何もできていない」が見えなくなります", before, after)
	}
}

func TestATickThatFinishedMovesTheSuccessTimestamp(t *testing.T) {
	const name = "test_worker_finished"
	before := time.Now().Unix()

	trackRun(context.Background(), name, func(context.Context) {})

	if got := value(metrics.SchedulerFailures.WithLabelValues(name)); got != 0 {
		t.Errorf("失敗回数 = %v, want 0", got)
	}
	ts := value(metrics.SchedulerLastSuccessTimestamp.WithLabelValues(name))
	if ts < float64(before) {
		t.Errorf("最終成功時刻が更新されていません (%v < %v)", ts, before)
	}
}

// 1回の tick で複数箇所が諦めたら、その数だけ数えること。
// 「1回でも失敗したら1」だと、ひとつ直しても数字が動かず、直ったのか
// 別の箇所が失敗しているのか分かりません。
func TestEveryPlaceThatGaveUpIsCounted(t *testing.T) {
	const name = "test_worker_multi"

	trackRun(context.Background(), name, func(ctx context.Context) {
		fail(ctx, errors.New("1"), "テスト: 1件目")
		fail(ctx, errors.New("2"), "テスト: 2件目")
		fail(ctx, errors.New("3"), "テスト: 3件目")
	})

	if got := value(metrics.SchedulerFailures.WithLabelValues(name)); got != 3 {
		t.Errorf("失敗回数 = %v, want 3", got)
	}
}

// fail は tick の外からでも落ちないこと。起動時に一度だけ走る初期化など、
// trackRun を通らない経路があります。記録先が無いときはログだけ出します。
func TestFailOutsideATickDoesNotPanic(t *testing.T) {
	fail(context.Background(), errors.New("x"), "テスト: tick の外")
	if failing(context.Background()) {
		t.Error("tick の外なのに失敗として扱われています")
	}
}

// failing が tick の状態を見ていること。上の検査だけだと、常に false を
// 返す実装でも通ります。
func TestFailingSeesTheTickState(t *testing.T) {
	trackRun(context.Background(), "test_worker_failing", func(ctx context.Context) {
		if failing(ctx) {
			t.Error("何も失敗していないのに failing が true です")
		}
		fail(ctx, errors.New("x"), "テスト")
		if !failing(ctx) {
			t.Error("失敗した後に failing が false のままです")
		}
	})
}
