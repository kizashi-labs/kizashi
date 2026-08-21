package detection

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// 抑制ルールの走査が途中で失敗したとき、それが呼び出し側に伝わること。
//
// ## なぜ実 DB では測れないのか
//
// `rows.Err()` が非 nil になるのは、**問い合わせが始まったあとに**落ちた
// ときです（接続が切れた、statement_timeout に当たった、サーバが止めた）。
// 実 DB で狙って起こすと、起こせたり起こせなかったりする検査になります
// —— **不安定な検査は無視されるようになり、無視される検査は消えます。**
//
// なので `Query` だけを差し替えます。落ちる `pgx.Rows` を返せば、
// 分岐は毎回同じところを通ります。
//
// ## 落ちたときに何が起きるか
//
// `return rules, nil` に倒すと、**途中まで読めたルールで全体を置き換えて
// 「成功」を返します。** 呼び出し側（SuppressionMatcher）はそれを
// 「いま有効な抑制はこれで全部」として取り込みます。
//
// 読めなかったぶんの抑制ルールは、**次に読み直すまで効きません。**
// 運用者からは「抑制が効いたり効かなかったりする」としか見えず、
// ログには何も残りません。
//
// ## この検査が要る理由
//
// 上流の「抑制の一本化」(#74) で、この経路は internal/suppression から
// ここへ移りました。**移った先を覆うテストは来ませんでした。**
// `rows.Err()` の走査（store/rows_err_returnable_test.go）は床に 28 の
// 余裕があるので、1 箇所消えても割れません。**数で留める検査は、
// 特定の 1 箇所を守れません。**

// failingRows は、読み終わったあとに失敗を報告する pgx.Rows。
//
// **1 行返してから落ちます。** 0 行だと「そもそも読めなかった」と
// 区別が付かず、「途中まで読めたぶんで置き換える」という壊れ方を
// 再現できません。
type failingRows struct {
	pgx.Rows
	left int
	err  error
}

func (r *failingRows) Next() bool {
	if r.left > 0 {
		r.left--
		return true
	}
	return false
}

func (r *failingRows) Scan(dest ...any) error { return errors.New("scan は使いません") }
func (r *failingRows) Err() error             { return r.err }
func (r *failingRows) Close()                 {}

type stubQuerier struct {
	rows pgx.Rows
	err  error
}

func (q stubQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return q.rows, q.err
}

// 走査が途中で失敗したら、その失敗が返ること。
//
// **`return rules, nil` に倒す変異は、ここで死にます。**
func TestASuppressionScanThatFailsPartWayIsNotReportedAsSuccess(t *testing.T) {
	boom := errors.New("走査が途中で切れました")
	l := &PoolSuppressionLoader{pool: stubQuerier{rows: &failingRows{left: 1, err: boom}}}

	rules, err := l.ListActiveSuppressions(context.Background())
	if err == nil {
		t.Fatalf("走査が失敗したのに成功が返りました（ルール %d 件）。\n"+
			"**途中まで読めたぶんで全体を置き換えて「これで全部」と答えています。**\n"+
			"読めなかった抑制ルールは次の読み直しまで効かず、ログにも残りません",
			len(rules))
	}
	if !errors.Is(err, boom) {
		t.Errorf("返った誤り = %v, want %v を含むもの。"+
			"**元の誤りを捨てると、何が起きたのか誰にも分かりません**", err, boom)
	}
}

// 走査が最後まで通ったら、読めたぶんが返ること。
//
// **上の検査だけだと「常に失敗を返す」実装が通ります。** 逆向きも留めます。
func TestASuppressionScanThatFinishesIsNotReportedAsFailure(t *testing.T) {
	l := &PoolSuppressionLoader{pool: stubQuerier{rows: &failingRows{left: 0}}}

	if _, err := l.ListActiveSuppressions(context.Background()); err != nil {
		t.Fatalf("走査は通ったのに誤りが返りました: %v。"+
			"**抑制が丸ごと効かなくなります**", err)
	}
}

// 問い合わせそのものが失敗したときも、黙って空を返さないこと。
func TestASuppressionQueryThatFailsIsNotAnEmptyRuleSet(t *testing.T) {
	boom := errors.New("問い合わせを拒否されました")
	l := &PoolSuppressionLoader{pool: stubQuerier{err: boom}}

	rules, err := l.ListActiveSuppressions(context.Background())
	if err == nil {
		t.Fatalf("問い合わせが失敗したのに成功が返りました（ルール %d 件）。"+
			"**「抑制ルールは 1 件も無い」と同じ姿です**", len(rules))
	}
	if !errors.Is(err, boom) {
		t.Errorf("返った誤り = %v, want %v を含むもの", err, boom)
	}
}

// pool を持たない構成で落ちないこと。
//
// **nil の *pgxpool.Pool を interface に入れると nil でなくなります。**
// 構築側でそこを潰しているので、潰し忘れをここで留めます。
func TestALoaderWithoutAPoolIsNotAFailure(t *testing.T) {
	for name, l := range map[string]*PoolSuppressionLoader{
		"構築子から": NewPoolSuppressionLoader(nil),
		"ゼロ値から": {},
	} {
		t.Run(name, func(t *testing.T) {
			rules, err := l.ListActiveSuppressions(context.Background())
			if err != nil || rules != nil {
				t.Errorf("pool 無しで rules=%v err=%v。"+
					"**抑制を切ってある構成が、毎回失敗として積まれます**", rules, err)
			}
		})
	}
}
