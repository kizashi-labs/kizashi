package detection

import (
	"context"
	"errors"
	"testing"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/tick"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// curate の見送り理由を記録できなかったときに、**その回が成功として
// 刻まれないこと。**
//
// 実測 (2026-08-12): この3つ（deferred / pending / builtin_duplicate）は
// `_, _ = s.db.Exec(…)` で捨てられていました。**`restart` に分類して
// いましたが、間違いでした** —— `curate_scheduler` の
// `trackRun(ctx, "curate_scheduler", s.tick)` から届くので、
// **「回」があります。**
//
// `internal/tick` の走査も挙げませんでした。3段たどりますが**同じ
// package の中だけ**で、`internal/scheduler` から `internal/detection`
// への呼び出しは1段目で見えなくなります。
//
// `tick.FailComponent` は両方の呼ばれ方に合います:
//
//	スケジューラから  部品ごとの件数 ＋ **その回を成功にしない**
//	管理APIから       回が無いので件数だけ

// stubCurateDB fails Exec on demand. Query is never reached by
// stampCurateState.
type stubCurateDB struct {
	err   error
	calls int
	last  struct {
		sql   string
		ids   []string
		state string
	}
}

func (s *stubCurateDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("使いません")
}

func (s *stubCurateDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	s.calls++
	s.last.sql = sql
	if len(args) == 2 {
		s.last.ids, _ = args[0].([]string)
		s.last.state, _ = args[1].(string)
	}
	return pgconn.CommandTag{}, s.err
}

func curateCounter() float64 {
	return counterValue(metrics.BackgroundFailures.WithLabelValues("curate_stamp"))
}

func TestAFailedCurateStampDoesNotLeaveTheRunLookingSuccessful(t *testing.T) {
	cases := []struct {
		name      string
		db        *stubCurateDB
		wantMoved float64
		wantFails int
	}{
		{
			name:      "書けなかったら、件数も回も動く",
			db:        &stubCurateDB{err: errors.New("書き込みを拒否されました")},
			wantMoved: 1,
			wantFails: 1,
		},
		{
			name: "書けたら、どちらも動かない",
			db:   &stubCurateDB{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := curateCounter()
			ctx := tick.WithState(context.Background())

			s := &CurateService{db: tc.db}
			s.stampCurateState(ctx, "deferred", []string{"r-1", "r-2"})

			if tc.db.calls != 1 {
				t.Fatalf("Exec の呼び出し回数 = %d, want 1", tc.db.calls)
			}
			if tc.db.last.state != "deferred" || len(tc.db.last.ids) != 2 {
				t.Errorf("渡した引数 = state %q / ids %v。"+
					"順番が入れ替わると、別の状態を刻みます",
					tc.db.last.state, tc.db.last.ids)
			}
			if moved := curateCounter() - before; moved != tc.wantMoved {
				t.Errorf("curate_stamp の失敗件数の増分 = %v, want %v",
					moved, tc.wantMoved)
			}
			if got := tick.Failures(ctx); got != tc.wantFails {
				t.Errorf("この回の失敗記録 = %d, want %d。**0 のままだと "+
					"last_success が押され、毎回失敗しているスケジューラが"+
					"健全なものと同じ姿になります**", got, tc.wantFails)
			}
		})
	}
}

// 空の一覧では問い合わせないこと。**毎周回、対象0件で UPDATE を投げる
// のは無駄なだけでなく、`WHERE id = ANY('{}')` が0行に当たったことと
// 「刻むものが無かった」ことを混ぜます。**
func TestNothingToStampIsNotAQuery(t *testing.T) {
	db := &stubCurateDB{err: errors.New("呼ばれてはいけません")}
	before := curateCounter()

	s := &CurateService{db: db}
	s.stampCurateState(context.Background(), "pending", nil)

	if db.calls != 0 {
		t.Errorf("Exec を %d 回呼びました。空の一覧では問い合わせません", db.calls)
	}
	if moved := curateCounter() - before; moved != 0 {
		t.Errorf("何もしていないのに失敗を報告しました (増分 %v)", moved)
	}
}

// 回の外（管理API）から呼ばれたときは、件数だけが動くこと。
// **`tick.FailComponent` が回を要求するようになったら、管理APIの経路が
// 落ちます。**
func TestAStampFailureOutsideARunStillCounts(t *testing.T) {
	before := curateCounter()

	s := &CurateService{db: &stubCurateDB{err: errors.New("書き込みを拒否されました")}}
	s.stampCurateState(context.Background(), "builtin_duplicate", []string{"r-1"})

	if moved := curateCounter() - before; moved != 1 {
		t.Errorf("curate_stamp の失敗件数の増分 = %v, want 1", moved)
	}
}
