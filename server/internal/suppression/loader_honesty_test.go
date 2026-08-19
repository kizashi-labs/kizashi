package suppression

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadFromDB dropped a rule on the floor in two places without saying so: a row
// that would not scan hit `continue`, and a conditions blob that would not parse
// went through `_ = json.Unmarshal`. Either way the rule stayed enabled in the
// console and suppressed nothing, and the only symptom was "the alert I
// suppressed keeps firing" — which reads as the suppression feature being
// broken rather than as one rule being unreadable.
//
// The dangerous direction was already closed, and that is worth recording
// because it is the first thing to check here. matchesAll ends with
//
//	return len(conds) > 0
//
// so a rule with no conditions matches nothing. Had it ended with `return true`
// — the ordinary way to write a conjunction over a loop — a rule whose
// conditions failed to parse would have matched every alert and silently
// suppressed the entire stream. The test below pins that, because it is one
// character away from catastrophe and nothing else in the tree says so.

func loaderPool(t *testing.T) *pgxpool.Pool {
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

// seedRule inserts one enabled suppression rule with the given raw conditions.
func seedRule(t *testing.T, pool *pgxpool.Pool, name, conditions string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO suppression_rules (name, description, enabled, conditions, duration_seconds)
		VALUES ($1, 'fixture', true, $2::jsonb, 0)`, name, conditions); err != nil {
		t.Fatalf("seed rule %q: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM suppression_rules WHERE name=$1`, name)
	})
}

// The load-bearing invariant: a rule with no usable conditions must not match.
//
// This is the difference between one inert rule and a platform that silently
// drops every alert, and it rests entirely on matchesAll's final line.
func TestARuleWithNoConditionsSuppressesNothing(t *testing.T) {
	alert := map[string]interface{}{
		"title": "anything at all", "severity": "9", "hostname": "host-1",
	}

	if matchesAll(nil, alert) {
		t.Error("条件が nil のルールがアラートに一致しました。" +
			"条件が解釈できなかったルールが全アラートを抑制することになります")
	}
	if matchesAll([]Condition{}, alert) {
		t.Error("条件が空のルールがアラートに一致しました。同上")
	}
	// And a real condition still works, or the two checks above prove nothing.
	if !matchesAll([]Condition{{Field: "title", Operator: "contains", Value: "anything"}}, alert) {
		t.Error("正しい条件が一致しません")
	}
	if matchesAll([]Condition{{Field: "title", Operator: "contains", Value: "nope"}}, alert) {
		t.Error("一致しない条件が一致しています")
	}
}

// The headline: a rule the loader cannot use does not join the running set, and
// the ones that are usable still do.
func TestUnusableRulesAreLeftOutRatherThanLeftInert(t *testing.T) {
	pool := loaderPool(t)
	ctx := context.Background()

	marker := uuid.NewString()[:8]
	good := "suppr-good-" + marker
	empty := "suppr-empty-" + marker
	wrongShape := "suppr-shape-" + marker

	conds, _ := json.Marshal([]Condition{
		{Field: "title", Operator: "contains", Value: "suppr-fixture-" + marker},
	})
	seedRule(t, pool, good, string(conds))
	seedRule(t, pool, empty, `[]`)
	// Valid jsonb, wrong shape for []Condition — this is what Unmarshal used to
	// swallow.
	seedRule(t, pool, wrongShape, `{"field":"title","operator":"eq","value":"x"}`)

	// **読めない行はここには置きません。** 別の検査に移しました
	// （TestARowThatCannotBeScannedFailsTheLoad）——
	// pgx は Scan の失敗で結果セットを閉じるので、その行は「飛ばされる」
	// のではなく、**そこから先が全部読まれません。** 読み込みは途中で
	// 終わり、そのことを言わずに成功を返していました。
	//
	// この検査が見たいのは「読めたが使えないルール」の扱いなので、
	// 途中で切れる行を混ぜると、下の件数の意味が変わります。

	e := NewEngine(pool)
	if err := e.LoadFromDB(ctx); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	inSet := map[string]bool{}
	for _, r := range e.GetRules() {
		inSet[r.Name] = true
	}
	if !inSet[good] {
		t.Errorf("正常なルールが読み込まれていません: %v", inSet)
	}
	for _, name := range []string{empty, wrongShape} {
		if inSet[name] {
			t.Errorf("使えないルール %q が稼働セットに入っています。"+
				"有効に見えて何も抑制しないため、"+
				"「抑制したはずのアラートが出続ける」としか現れません", name)
		}
	}

	// The rejection reasons must stay apart. They present identically to the
	// operator — the alert keeps firing — so the only place the difference
	// exists is here, and two overlapping guards mean either one alone still
	// keeps the rule out of the set. Counting them separately is what makes
	// dropping one of the guards visible.
	st := e.LastLoad()
	if st.Loaded < 1 {
		t.Errorf("読み込めたルールが %d 件です", st.Loaded)
	}
	if st.Unparseable != 1 {
		t.Errorf("解釈できなかったルール = %d 件, 1件を期待 (%+v)。"+
			"条件の Unmarshal エラーを捨てると、"+
			"「条件が空」の方のガードに吸収されて理由が消えます", st.Unparseable, st)
	}
	if st.EmptyConditions != 1 {
		t.Errorf("条件が空のルール = %d 件, 1件を期待 (%+v)", st.EmptyConditions, st)
	}
	// **`Unreadable` はここでは 0 です。** 読めない行は
	// `TestARowThatCannotBeScannedFailsTheLoad` に移しました ——
	// pgx は Scan の失敗で結果セットを閉じるので、その行は「1件の
	// 読めなかったルール」ではなく、**そこから先すべての打ち切り**です。
	// 件数として数えると、打ち切られた分が「1件」に見えます。
	if st.Unreadable != 0 {
		t.Errorf("読めなかったルール = %d 件, 0件を期待 (%+v)", st.Unreadable, st)
	}
	if st.Rejected() != 2 {
		t.Errorf("除外されたルール = %d 件, 2件を期待 (%+v)", st.Rejected(), st)
	}

	// And the usable one actually suppresses.
	suppressed, by := e.ShouldSuppress(map[string]interface{}{
		"title": "suppr-fixture-" + marker + " noisy alert",
	})
	if !suppressed || by != good {
		t.Errorf("正常なルールが抑制していません: suppressed=%v by=%q", suppressed, by)
	}
	// An unrelated alert must still get through.
	if s, _ := e.ShouldSuppress(map[string]interface{}{"title": "unrelated"}); s {
		t.Error("無関係なアラートが抑制されました")
	}
}

// And the loader must not go back to discarding these two errors. Both are one
// `_ =` away, and neither has a symptom at the point it happens.
func TestTheLoaderDoesNotDiscardItsErrors(t *testing.T) {
	b, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatalf("read engine.go: %v", err)
	}
	src := string(b)

	if contains(src, "_ = json.Unmarshal(condJSON") {
		t.Error("条件の解釈エラーを捨てています。" +
			"ルールは有効なまま稼働セットに残り、何も抑制しません")
	}
	if !contains(src, "return len(conds) > 0") {
		t.Error("matchesAll が空の条件集合で false を返さなくなっています。" +
			"条件を解釈できなかったルールが全アラートに一致します — " +
			"抑制機構としては最悪の壊れ方です")
	}
}

func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// 走査が途中で切れたら、**読み込みは失敗として返ること。**
//
// pgx は Scan の失敗で結果セットを閉じます。**その行が飛ばされるのでは
// なく、そこから先が全部読まれません。** 直す前は `rows.Err()` を
// `slog.Warn` に落として `nil` を返していたので:
//
//   - 稼働セットが、途中までのルールで置き換わる
//   - `LastLoad().Loaded` が、その途中までの件数を「読み込めた件数」として
//     記録する
//   - 呼び出し側は成功として先へ進む
//
// **抑制したはずのルールが効いていないことに、気づく手掛かりがありません。**
func TestARowThatCannotBeScannedFailsTheLoad(t *testing.T) {
	pool := loaderPool(t)
	ctx := context.Background()

	marker := uuid.NewString()[:8]
	conds, _ := json.Marshal([]Condition{
		{Field: "title", Operator: "contains", Value: "suppr-scan-" + marker},
	})
	good := "suppr-scan-good-" + marker
	seedRule(t, pool, good, string(conds))

	e := NewEngine(pool)
	if err := e.LoadFromDB(ctx); err != nil {
		t.Fatalf("下準備の読み込みに失敗しました: %v", err)
	}
	before := len(e.GetRules())
	if before < 1 {
		t.Fatalf("下準備のルールが読み込まれていません: %d", before)
	}

	// created_at はスキーマ上 NULL 可ですが `time.Time` に読みます。
	// **NULL が1行あると、そこで結果セットが閉じます。**
	unreadable := "suppr-unreadable-" + marker
	if _, err := pool.Exec(ctx, `
		INSERT INTO suppression_rules (name, description, enabled, conditions, duration_seconds, created_at)
		VALUES ($1, 'fixture', true, $2::jsonb, 0, NULL)`, unreadable, string(conds)); err != nil {
		t.Fatalf("seed unreadable rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM suppression_rules WHERE name=$1`, unreadable)
	})

	err := e.LoadFromDB(ctx)
	if err == nil {
		t.Fatal("**読み出しが途中で切れたのに、読み込みは成功を返しました。** " +
			"稼働セットは途中までのルールで置き換わり、件数だけが" +
			"「読み込めた件数」として残ります")
	}

	// **途中までのもので置き換えないこと。** 失敗したときに前のルールを
	// 捨てると、抑制が丸ごと消えます。
	if got := len(e.GetRules()); got < before {
		t.Errorf("稼働ルールが %d 件から %d 件に減りました。"+
			"**読み込めなかったときは、前のルールを残します**", before, got)
	}
}
