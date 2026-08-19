package scheduler

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/edr-platform/server/internal/tick"
)

// pgx は Query がエラー無しで nil の rows を返すことはありませんが、
// 呼び出し側にはその防御が書いてあります。**その枝で報告するときに
// 渡す error がありません** —— nil を渡すと「失敗したのに error が
// 無い」ログになるので、名前のある1つを使います。
var errNoRowsReturned = errors.New("クエリが行を返しませんでした（error は nil）")

// Every background worker in this package runs on a ticker, and until now
// almost none of them left a trace that they had run.
//
// Forty workers, three of which emitted any metric, and no run-record table
// anywhere. From outside a running process, "woke up and had nothing to do"
// and "has never run once" were the same observation: nothing.
//
// hunt_scheduler is what that costs. It wakes every fifteen minutes, finds
// that saved_hunt_queries has no `scheduled` column, and returns. It has
// executed zero hunts on every deployment that has ever existed, and the only
// way anyone found out was by reading the code. schema_gate_test.go now
// catches that particular shape — a probe the migrated schema cannot satisfy —
// but that is a subset. A worker can stop running for reasons no static check
// will ever see: a panic in a sibling goroutine, a context cancelled early, a
// registration quietly dropped from cmd/api.
//
// trackRun is the answer to the general case. It wraps the call inside the
// select rather than the loop around it, on purpose: these forty loops are not
// the same shape. Some run once at startup and some deliberately wait out an
// interval; dead_agent_cleanup arms a timer and a ticker; darkweb_scheduler
// has one ticker for a light sync and a daily 03:00 deadline for the full one.
// A single loop helper would have had to flatten all of that, and rewriting
// thirty-nine working loops to add a counter is the kind of change that
// introduces the bug it was meant to catch.

// trackRun runs fn and reports that it finished.
//
// The record is written after fn returns, deliberately. A counter incremented
// before the work would climb just as steadily for a worker that panics on
// every tick, which is the opposite of what it is for.
func trackRun(ctx context.Context, name string, fn func(context.Context)) {
	tick.Run(ctx, name, fn)
}

// ── giving up mid-tick ───────────────────────────────────────────────────────
//
// The counter above says the worker is running. It does not say the worker is
// doing anything, and those are different facts: trackRun increments whether
// the tick renewed forty certificates or returned on its first query error.
// A worker failing every single tick has a counter climbing exactly as
// steadily as a healthy one.
//
// これらのワーカーには報告する相手がいません。呼び出し側は次の周回です。
// なので失敗の行き先はどこにも無く、107箇所が slog に書いて return して
// いました。ログは、見に行った人にだけ届きます。証明書の更新が3日前から
// 毎回失敗していても、画面に出るのは「更新された証明書が無い」だけで、
// 更新が要らなかったのと区別がつきません。
//
// fail はその行き先です。ログは今まで通り出したうえで、この回が仕事を
// 終えられなかったことを tick 自身に記録します。trackRun がそれを
// edr_scheduler_failures_total と last_success に落とすので、
// 「回っているが何もできていない」が外から見えます。
//
// 呼び出し側の制御は変えません。値を返すのも、そこで戻るのも今まで通り
// です。変わるのは、それが誰かに届くかどうかだけです。
//
// **本体は `internal/tick` に移しました。** この package の中でしか
// 使えないままだと、外の 37 のワーカーが同じ形で報告できません。
// ここに残しているのは、この package の 28 か所の呼び出しを動かさない
// ためです。
func fail(ctx context.Context, err error, msg string, args ...any) {
	tick.Fail(ctx, err, msg, args...)
}

// tableMissing reports whether err is PostgreSQL 42P01 (undefined_table).
//
// **「まだマイグレーションが当たっていない」だけが、書けなくてよい
// 唯一の理由です。** DB が応答しない・権限が無い・時間切れは、どれも
// 「書けなかった」で、黙ってよい理由になりません。
// `internal/api/handlers` に同じ判断があります（あちらは `absent` の
// 一部として使われています）。
func tableMissing(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// failing reports whether this tick has already given up on something.
// テストと、同じ回で二重に数えたくない箇所のためです。
func failing(ctx context.Context) bool {
	return tick.Failing(ctx)
}
