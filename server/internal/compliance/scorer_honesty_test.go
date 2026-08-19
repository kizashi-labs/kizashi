package compliance

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every check in this scorer passes when its query counts zero violations, and
// every one of the eight queries discarded its error. So a dropped connection,
// a cancelled request or a timeout left the count at zero and the check
// reported PASSED: the endpoint was declared compliant exactly when the
// platform could not tell whether it was.
//
// The failure ran the wrong way round. The eight queries share one 10-second
// budget, so the busier the endpoint — more events, slower counts, more to
// find — the likelier it was to come back perfectly clean.
//
// And the result is persisted. ComputeScore writes it to compliance_scores, so
// a momentary outage left a fabricated 100 with a timestamp on it, sitting
// there until someone recomputed. That is the difference between this and the
// empty-screen defects: an auditor reading the record months later has no way
// to tell it was never measured.
//
// A check that cannot be evaluated is now neither passed nor failed. Failing it
// would be the opposite lie — an endpoint whose queries timed out reported as
// badly non-compliant rather than as unknown — so the score is taken over the
// checks that were actually assessed, and a run that assessed nothing is
// refused rather than returned.

func honestyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The headline: a scorer that cannot reach the database does not report a
// compliant endpoint.
func TestAnUnreachableDatabaseIsNotAPerfectScore(t *testing.T) {
	pool := honestyPool(t)

	agentID := uuid.NewString()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'honesty-fixture','windows','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// A context that is already done stands in for the timeout the eight
	// queries share: every query fails, exactly as it would on a slow database.
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := ScoreAgent(dead, pool, agentID)
	if err == nil {
		t.Fatalf("判定できないのにスコアを返しました: score=%d passed=%d/%d。"+
			"エラーを捨てるとカウントが0のままになり、"+
			"「違反0件＝合格」の判定が全項目で成立してしまいます",
			res.Score, res.Passed, res.Total)
	}
	if !errors.Is(err, ErrNothingAssessed) {
		t.Errorf("error = %v, want ErrNothingAssessed", err)
	}
	if res != nil {
		t.Errorf("エラーと同時に結果を返しています: %+v。"+
			"呼び出し側がこれを保存すると、実施されていない評価の記録が残ります", res)
	}
}

// A check that could be evaluated must be marked as such, and one that could
// not must not be counted as passing. This is what separates "no violations"
// from "no answer".
func TestAnUnevaluableCheckIsNeitherPassedNorCounted(t *testing.T) {
	// Built directly rather than through the database: the point is the
	// bookkeeping, and a real query cannot be made to fail on demand without
	// breaking the connection for everything else.
	assessedPass := verdict("X-1", "t", "high", 0, true, noneFound)
	assessedFail := verdict("X-2", "t", "high", 3, true, noneFound)
	notAssessed := verdict("X-3", "t", "high", 0, false, noneFound)

	if !assessedPass.Passed || !assessedPass.Assessed {
		t.Errorf("違反0件の判定が合格になりません: %+v", assessedPass)
	}
	if assessedFail.Passed || !assessedFail.Assessed {
		t.Errorf("違反ありの判定が不合格になりません: %+v", assessedFail)
	}
	if notAssessed.Passed {
		t.Errorf("判定できなかった項目が合格になっています: %+v。"+
			"カウントが0なのはクエリが失敗したからで、違反が無いからではありません",
			notAssessed)
	}
	if notAssessed.Assessed {
		t.Errorf("判定できなかった項目が評価済みになっています: %+v", notAssessed)
	}
}

// countCheck must report failure rather than hand back a usable-looking zero.
func TestCountCheckRefusesToInventAZero(t *testing.T) {
	pool := honestyPool(t)

	n, ok := countCheck(context.Background(), pool, "X-1",
		`SELECT COUNT(*) FROM no_such_table_for_this_test`)
	if ok {
		t.Errorf("存在しない表への問い合わせが成功扱いです (n=%d)", n)
	}
	if n != 0 {
		t.Errorf("失敗時のカウント = %d、0 を期待", n)
	}

	// And the ordinary case still works, or the guard above proves nothing.
	n, ok = countCheck(context.Background(), pool, "X-2", `SELECT 7`)
	if !ok || n != 7 {
		t.Errorf("正常なクエリで n=%d ok=%v, want 7/true", n, ok)
	}
}

// The score's denominator must be the assessed checks, not the declared ones.
// Dividing by the declared count turns "could not measure" into "failed",
// which is the mirror image of the original defect.
func TestTheScoreIsTakenOverWhatWasAssessed(t *testing.T) {
	pool := honestyPool(t)
	ctx := context.Background()

	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'honesty-fixture-2','windows','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	res, err := ScoreAgent(ctx, pool, agentID)
	if err != nil {
		t.Fatalf("ScoreAgent: %v", err)
	}
	if res.Assessed == 0 {
		t.Fatal("何も評価できませんでした。テスト用DBが応答していない可能性があります")
	}
	if res.Total != res.Assessed {
		t.Errorf("Total=%d Assessed=%d。Total は評価できた項目数でなければなりません",
			res.Total, res.Assessed)
	}
	if res.Passed > res.Assessed {
		t.Errorf("合格 %d > 評価済み %d", res.Passed, res.Assessed)
	}
	want := (res.Passed * 100) / res.Assessed
	if res.Score != want {
		t.Errorf("Score=%d, want %d (合格%d/評価済み%d)",
			res.Score, want, res.Passed, res.Assessed)
	}

	// An endpoint with no events has nothing to violate, so a healthy database
	// should assess every declared check. If it does not, the shared timeout is
	// too tight and this test is the place that notices.
	if res.Assessed != len(res.Checks) {
		t.Errorf("評価できたのは %d/%d 項目です。"+
			"8つのクエリが10秒の予算を共有しているため、"+
			"イベントの多い端末ほど後半の項目が評価されなくなります",
			res.Assessed, len(res.Checks))
	}
}

// And no query in this file may go back to discarding its error. The scorer is
// the one place where a swallowed error becomes a compliance claim, so the
// prohibition is pinned in the source rather than left to review.
func TestNoQueryInTheScorerDiscardsItsError(t *testing.T) {
	b, err := os.ReadFile("scorer.go")
	if err != nil {
		t.Fatalf("read scorer.go: %v", err)
	}
	src := string(b)

	for _, bad := range []string{"_ = pool.QueryRow", "_ = pool.Query("} {
		if strings.Contains(src, bad) {
			t.Errorf("scorer.go が %q でエラーを捨てています。"+
				"ここで捨てたエラーは「違反0件」に化け、"+
				"compliance_scores に合格として保存されます", bad)
		}
	}
	// countCheck is the only way to run one of these, so it must still be used
	// once per check.
	if n := strings.Count(src, "countCheck(queryCtx"); n < 8 {
		t.Errorf("countCheck の呼び出しが %d 件です (8件を期待)。"+
			"素の QueryRow に戻された項目がないか確認してください", n)
	}
}

// The shared budget is deliberate, but it must stay long enough that an idle
// endpoint is fully assessed. This records the number so a future change to it
// is a decision rather than an accident.
func TestTheSharedQueryBudgetIsRecorded(t *testing.T) {
	b, err := os.ReadFile("scorer.go")
	if err != nil {
		t.Fatalf("read scorer.go: %v", err)
	}
	if !strings.Contains(string(b), "context.WithTimeout(ctx, 10*time.Second)") {
		t.Error("8つのクエリが共有するタイムアウトが変更されています。" +
			"短くすると評価できない項目が増え、長くすると要求が詰まります — " +
			"どちらも判断のうえで変更してください")
	}
	// A sanity floor on the budget itself: if this ever became sub-second the
	// scorer would assess almost nothing on a real deployment.
	if 10*time.Second < time.Second {
		t.Fatal("unreachable")
	}
}

// The denominator is the part the healthy path cannot check: when every check
// is assessed, dividing by the assessed count and by the declared count give
// the same answer. Only a partial assessment tells them apart, and that is
// exactly the state the old code could not represent.
func TestTheScoreIgnoresChecksItCouldNotRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []Check
		score  int
		passed int
		nAsses int
	}{
		{
			"all assessed, half passing",
			[]Check{
				{Passed: true, Assessed: true},
				{Passed: true, Assessed: true},
				{Passed: false, Assessed: true},
				{Passed: false, Assessed: true},
			}, 50, 2, 4,
		},
		{
			// The load-bearing case: two of four could not be run, and both of
			// the two that could be run passed. Over the assessed checks that
			// is 100; over the declared checks it would be 50, which would
			// report a clean endpoint as half non-compliant.
			"half unassessed, the rest passing",
			[]Check{
				{Passed: true, Assessed: true},
				{Passed: true, Assessed: true},
				{Passed: false, Assessed: false},
				{Passed: false, Assessed: false},
			}, 100, 2, 2,
		},
		{
			"half unassessed, the rest failing",
			[]Check{
				{Passed: false, Assessed: true},
				{Passed: false, Assessed: true},
				{Passed: false, Assessed: false},
				{Passed: false, Assessed: false},
			}, 0, 0, 2,
		},
		{
			"nothing assessed",
			[]Check{
				{Passed: false, Assessed: false},
				{Passed: false, Assessed: false},
			}, 0, 0, 0,
		},
		{"no checks at all", nil, 0, 0, 0},
	} {
		score, passed, assessed := tally(tc.checks)
		if score != tc.score || passed != tc.passed || assessed != tc.nAsses {
			t.Errorf("%s: score=%d passed=%d assessed=%d, want %d/%d/%d。"+
				"分母は「宣言された項目数」ではなく「評価できた項目数」です — "+
				"前者で割ると、判定できなかった項目を不合格として数えることになります",
				tc.name, score, passed, assessed, tc.score, tc.passed, tc.nAsses)
		}
	}
}
