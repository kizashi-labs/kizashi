// Package tick records that a background worker ran, and whether it got
// anything done.
//
// **`internal/scheduler` の外にも、周期的に回る仕事が 37 か所あります。**
// 実測 (2026-08-12): ticker を持つ箇所は 73、うち `internal/scheduler` が
// 36、その外が 37。**外の 37 は1つも run を記録していませんでした。**
//
// `internal/scheduler` には既にこの仕組みがありました（`heartbeat.go`）。
// 「40 のワーカーのうち、計測を出していたのは3つ」という実測から作られた
// もので、**その campaign は package の中で止まっていました。** 外の
// ワーカーは、動いているのか、一度も動いていないのかを、外から区別
// できません。
//
// もう1つ、前回の続きがあります。`Fail` は `internal/scheduler` の中でしか
// 使えませんでした（`tickState` が package 内）。外の 16 か所は
// `slog.Error` 止まりで、**「回っているが何もできていない」が計測に
// 出ません。** ここへ出したので、両側が同じ形で報告できます。
package tick

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/metrics"
)

type stateKey struct{}

type state struct {
	mu sync.Mutex
	n  int
}

func (s *state) add() {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}

func (s *state) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// Run runs fn and records that it finished.
//
// 記録は fn が戻ってから書きます。**先に数えると、毎回パニックする
// ワーカーの計数も同じように増えます** —— それはこの仕組みの逆です。
func Run(ctx context.Context, name string, fn func(context.Context)) {
	st := &state{}
	start := time.Now()
	fn(context.WithValue(ctx, stateKey{}, st))
	metrics.SchedulerRunSeconds.WithLabelValues(name).Observe(time.Since(start).Seconds())
	metrics.SchedulerRuns.WithLabelValues(name).Inc()
	metrics.SchedulerLastRunTimestamp.WithLabelValues(name).Set(float64(time.Now().Unix()))
	if n := st.count(); n > 0 {
		metrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))
		return
	}
	metrics.SchedulerLastSuccessTimestamp.WithLabelValues(name).Set(float64(time.Now().Unix()))
}

// Fail records that this run could not finish part of its work, and logs it.
//
// **ログは今まで通り出します。変わるのは、それが誰かに届くかどうかだけ**
// です。`ctx` が `Run` の渡したものでないときは記録先が無いので、ログだけ
// 出して静かに続けます（起動時に一度だけ走る初期化など、回の外から
// 呼ばれる経路があるため）。
func Fail(ctx context.Context, err error, msg string, args ...any) {
	slog.Error(msg, append(args, "error", err)...)
	if st, ok := ctx.Value(stateKey{}).(*state); ok {
		st.add()
	}
}

// FailComponent records a component failure **and** marks this run as
// unfinished.
//
// **綴りが3つありました。** 実測 (2026-08-12):
//
//	fail(ctx, err, msg)                  147 箇所（internal/scheduler の中だけ）
//	metrics.BackgroundFailed(comp, ...)   72 箇所（12 package）
//	tick.Fail(ctx, err, msg)              10 箇所
//
// どれも「失敗を報告する」ですが、**答える問いが違います**:
//
//	BackgroundFailed  この部品が失敗した（edr_background_failures_total）
//	Fail              この回が仕事を終えられなかった（last_success を押さない）
//
// **`Run` で回している仕事の中で `BackgroundFailed` だけを使うと、
// 失敗は数えられるのに、その回は成功として刻まれます。** 実測 (2026-08-12):
// `Run` の中で `BackgroundFailed` を呼んでも、この回の記録は 0 件のままで、
// `last_success` が更新されます —— 毎回失敗しているワーカーが、
// 健全なワーカーと同じ姿で見えます。
//
// 実測: `Run` で回している 14 の仕事のうち **13 が `BackgroundFailed` を
// 使っていました**（6 つはそれだけ、7 つは `Fail` と混在）。
//
// ここは両方します。**部品ごとの件数は残したまま**、この回を
// 「終えられなかった」に落とします。
func FailComponent(ctx context.Context, component string, err error, msg string, args ...any) {
	metrics.BackgroundFailed(component, err, msg, args...)
	if st, ok := ctx.Value(stateKey{}).(*state); ok {
		st.add()
	}
}

// Failing reports whether this run has already given up on something.
func Failing(ctx context.Context) bool {
	st, ok := ctx.Value(stateKey{}).(*state)
	return ok && st.count() > 0
}

// WithState returns a ctx carrying a fresh record. **検査のためのものです** ——
// `Run` を通さずに `Fail` の届き先を用意したいときに使います。
func WithState(ctx context.Context) context.Context {
	return context.WithValue(ctx, stateKey{}, &state{})
}

// Failures reports how many times Fail was called under this ctx.
// **検査のためのものです。**
func Failures(ctx context.Context) int {
	st, ok := ctx.Value(stateKey{}).(*state)
	if !ok {
		return 0
	}
	return st.count()
}
