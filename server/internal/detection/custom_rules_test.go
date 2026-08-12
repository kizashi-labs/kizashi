package detection

// ユーザー定義アラートルールの評価。
//
// この機能は「UI から作れるが何も起きない」状態で放置されていた
// (評価する側が無く、唯一の参照だった sigma_db.go のクエリは存在しない列を
// 見ていた)。二度と静かに死なないよう、評価の意味論をここで固定する。

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func condJSON(t *testing.T, conds []CustomRuleCondition) []byte {
	t.Helper()
	b, err := json.Marshal(conds)
	if err != nil {
		t.Fatalf("marshal conditions: %v", err)
	}
	return b
}

// ruleWith は 1 条件のルールを組み立てる。
func ruleWith(t *testing.T, field, op, value string) CustomRule {
	t.Helper()
	conds := []CustomRuleCondition{{Field: field, Operator: op, Value: value}}
	r := CustomRule{
		ID:             "r1",
		Name:           "itest-rule",
		Conditions:     conds,
		ThresholdCount: 1,
		Severity:       7,
		AlertTitle:     "itest alert",
	}
	r.compiled = compileRegexConditions(r.Name, conds)
	return r
}

func evaluatorWith(rules ...CustomRule) *CustomRuleEvaluator {
	e := NewCustomRuleEvaluator()
	e.rules = rules
	return e
}

// TestCustomRule_OperatorSemantics は各オペレータの意味を固定する。
func TestCustomRule_OperatorSemantics(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		ruleVal  string
		eventVal interface{}
		want     bool
	}{
		{"eq 一致", "eq", "powershell.exe", "powershell.exe", true},
		{"eq は大文字小文字を無視", "eq", "PowerShell.exe", "powershell.exe", true},
		{"eq 不一致", "eq", "cmd.exe", "powershell.exe", false},
		{"ne 一致", "ne", "cmd.exe", "powershell.exe", true},
		{"contains 一致", "contains", "shell", "powershell.exe", true},
		{"contains 不一致", "contains", "python", "powershell.exe", false},
		{"regex 一致", "regex", `^power.*\.exe$`, "powershell.exe", true},
		{"regex 不一致", "regex", `^cmd`, "powershell.exe", false},
		{"gt 一致", "gt", "5", 9, true},
		{"gt 不一致", "gt", "9", 5, false},
		{"gte 境界", "gte", "5", 5, true},
		{"lt 一致", "lt", "5", 3, true},
		{"lte 境界", "lte", "5", 5, true},
		// 数値でない値の比較は一致させない。文字列を黙って 0 と見なすと
		// 「severity > 5」が全イベントに当たるような事故になる。
		{"数値比較で非数値", "gt", "5", "abc", false},
		// 未知のオペレータは一致させない。誤記が全イベント発報になるのは危険。
		{"未知のオペレータ", "matches", "x", "x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := evaluatorWith(ruleWith(t, "f", tc.op, tc.ruleVal))
			got := len(e.EvaluateEvent(map[string]interface{}{"f": tc.eventVal})) == 1
			if got != tc.want {
				t.Errorf("一致 = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCustomRule_MissingFieldDoesNotMatch は対象フィールドが無いイベントで
// 一致しないこと。存在しないフィールドを空文字として扱うと
// 「その項目が空文字と等しい」というルールが全イベントに当たってしまう。
func TestCustomRule_MissingFieldDoesNotMatch(t *testing.T) {
	e := evaluatorWith(ruleWith(t, "process_name", "eq", ""))
	if n := len(e.EvaluateEvent(map[string]interface{}{"hostname": "h1"})); n != 0 {
		t.Errorf("一致件数 = %d, want 0", n)
	}
}

// TestCustomRule_AllConditionsMustMatch は複数条件が AND であること。
func TestCustomRule_AllConditionsMustMatch(t *testing.T) {
	conds := []CustomRuleCondition{
		{Field: "process_name", Operator: "eq", Value: "powershell.exe"},
		{Field: "command_line", Operator: "contains", Value: "-enc"},
	}
	r := CustomRule{ID: "r1", Name: "and-rule", Conditions: conds, ThresholdCount: 1, AlertTitle: "t"}
	r.compiled = compileRegexConditions(r.Name, conds)
	e := evaluatorWith(r)

	both := map[string]interface{}{"process_name": "powershell.exe", "command_line": "powershell -enc AAA"}
	if n := len(e.EvaluateEvent(both)); n != 1 {
		t.Errorf("両方一致で %d 件, want 1", n)
	}
	onlyOne := map[string]interface{}{"process_name": "powershell.exe", "command_line": "powershell -File x.ps1"}
	if n := len(e.EvaluateEvent(onlyOne)); n != 0 {
		t.Errorf("片方だけ一致で %d 件, want 0 (AND になっていない)", n)
	}
}

// TestCustomRule_EmptyConditionsNeverMatch は条件が空のルールが
// 全イベントを発報しないこと。設定ミスで作られた空ルールの被害が大きすぎる。
func TestCustomRule_EmptyConditionsNeverMatch(t *testing.T) {
	e := evaluatorWith(CustomRule{ID: "r1", Name: "empty", ThresholdCount: 1})
	if n := len(e.EvaluateEvent(map[string]interface{}{"anything": "x"})); n != 0 {
		t.Errorf("条件が空のルールが %d 件一致した, want 0", n)
	}
}

// TestCustomRule_EventTypeFilter は event_type による絞り込み。
func TestCustomRule_EventTypeFilter(t *testing.T) {
	r := ruleWith(t, "f", "eq", "v")
	r.EventType = "process"
	e := evaluatorWith(r)

	if n := len(e.EvaluateEvent(map[string]interface{}{"type": "process", "f": "v"})); n != 1 {
		t.Errorf("対象の event_type で %d 件, want 1", n)
	}
	if n := len(e.EvaluateEvent(map[string]interface{}{"type": "network", "f": "v"})); n != 0 {
		t.Errorf("対象外の event_type で %d 件, want 0", n)
	}
}

// TestCustomRule_ThresholdAndWindow は閾値と時間窓の挙動。
// 「5分に10回」のようなルールが 1 回目で鳴っては意味がない。
func TestCustomRule_ThresholdAndWindow(t *testing.T) {
	conds := []CustomRuleCondition{{Field: "f", Operator: "eq", Value: "v"}}
	r := CustomRule{
		ID: "r1", Name: "threshold", Conditions: conds,
		ThresholdCount: 3, TimeWindowSeconds: 60, AlertTitle: "t",
	}
	r.compiled = compileRegexConditions(r.Name, conds)
	e := evaluatorWith(r)

	evt := map[string]interface{}{"f": "v", "agent_id": "a1"}
	base := time.Unix(1000, 0)

	if n := len(e.evaluateAt(evt, base)); n != 0 {
		t.Errorf("1 回目で %d 件発報, want 0", n)
	}
	if n := len(e.evaluateAt(evt, base.Add(time.Second))); n != 0 {
		t.Errorf("2 回目で %d 件発報, want 0", n)
	}
	got := e.evaluateAt(evt, base.Add(2*time.Second))
	if len(got) != 1 {
		t.Fatalf("3 回目で %d 件発報, want 1", len(got))
	}
	if got[0].Count != 3 {
		t.Errorf("Count = %d, want 3", got[0].Count)
	}

	// 発報後は窓がクリアされるので、次の発報にはまた 3 回必要。
	// クリアしないと閾値到達後は 1 件ごとに鳴り続ける。
	if n := len(e.evaluateAt(evt, base.Add(3*time.Second))); n != 0 {
		t.Errorf("発報直後の 1 件で %d 件発報, want 0 (窓がクリアされていない)", n)
	}
}

// TestCustomRule_WindowExpires は窓を過ぎた計数が捨てられること。
// 捨てないと「5分に10回」が「累計10回」になり、いつか必ず鳴る。
func TestCustomRule_WindowExpires(t *testing.T) {
	conds := []CustomRuleCondition{{Field: "f", Operator: "eq", Value: "v"}}
	r := CustomRule{
		ID: "r1", Name: "window", Conditions: conds,
		ThresholdCount: 2, TimeWindowSeconds: 10, AlertTitle: "t",
	}
	r.compiled = compileRegexConditions(r.Name, conds)
	e := evaluatorWith(r)

	evt := map[string]interface{}{"f": "v", "agent_id": "a1"}
	base := time.Unix(1000, 0)

	e.evaluateAt(evt, base)
	// 窓 (10秒) を超えて 2 件目。古い 1 件は落ちるので発報しない。
	if n := len(e.evaluateAt(evt, base.Add(30*time.Second))); n != 0 {
		t.Errorf("窓外の 2 件目で %d 件発報, want 0 (古い計数が残っている)", n)
	}
}

// TestCustomRule_ThresholdIsPerAgent は閾値がエージェントごとに数えられること。
// 全体で合算すると、別々のホストで 1 回ずつ起きただけで鳴る。
func TestCustomRule_ThresholdIsPerAgent(t *testing.T) {
	conds := []CustomRuleCondition{{Field: "f", Operator: "eq", Value: "v"}}
	r := CustomRule{
		ID: "r1", Name: "per-agent", Conditions: conds,
		ThresholdCount: 2, TimeWindowSeconds: 60, AlertTitle: "t",
	}
	r.compiled = compileRegexConditions(r.Name, conds)
	e := evaluatorWith(r)

	base := time.Unix(1000, 0)
	e.evaluateAt(map[string]interface{}{"f": "v", "agent_id": "a1"}, base)
	if n := len(e.evaluateAt(map[string]interface{}{"f": "v", "agent_id": "a2"}, base)); n != 0 {
		t.Errorf("別エージェントの 1 件目で %d 件発報, want 0 (合算されている)", n)
	}
}

// TestCustomRule_InvalidRegexNeverMatches は不正な正規表現の条件が
// 一致しないこと。コンパイル失敗を「常に一致」にすると全イベントが鳴る。
func TestCustomRule_InvalidRegexNeverMatches(t *testing.T) {
	e := evaluatorWith(ruleWith(t, "f", "regex", "([unclosed"))
	if n := len(e.EvaluateEvent(map[string]interface{}{"f": "anything"})); n != 0 {
		t.Errorf("不正な正規表現で %d 件一致, want 0", n)
	}
}

// ─── DB 読み込み ─────────────────────────────────────────────

func customRulesPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed custom rule tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedCustomRule(t *testing.T, pool *pgxpool.Pool, name string, enabled bool, conds []CustomRuleCondition) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO custom_alert_rules
		    (name, description, enabled, event_type, conditions,
		     threshold_count, time_window_seconds, severity, alert_title)
		VALUES ($1, 'itest', $2, 'process', $3, 1, 300, 7, $4)`,
		name, enabled, condJSON(t, conds), name+" fired")
	if err != nil {
		t.Fatalf("seed rule %s: %v", name, err)
	}
}

// TestLoadFromDB_LoadsOnlyEnabledRules は有効なルールだけ読むこと。
// この読み込みが壊れていたのが、機能全体が死んでいた原因そのもの。
func TestLoadFromDB_LoadsOnlyEnabledRules(t *testing.T) {
	pool := customRulesPool(t)
	ctx := context.Background()

	del := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM custom_alert_rules WHERE name LIKE 'ITestCR%'`)
	}
	del()
	t.Cleanup(del)

	conds := []CustomRuleCondition{{Field: "process_name", Operator: "eq", Value: "itest.exe"}}
	seedCustomRule(t, pool, "ITestCR-on", true, conds)
	seedCustomRule(t, pool, "ITestCR-off", false, conds)

	e := NewCustomRuleEvaluator()
	if err := e.LoadFromDB(ctx, pool); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	var names []string
	e.mu.RLock()
	for _, r := range e.rules {
		if len(r.Name) >= 7 && r.Name[:7] == "ITestCR" {
			names = append(names, r.Name)
		}
	}
	e.mu.RUnlock()

	if len(names) != 1 || names[0] != "ITestCR-on" {
		t.Fatalf("読み込まれたルール = %v, want [ITestCR-on]", names)
	}

	// 読み込んだルールが実際に評価に効くこと。読み込めても評価に
	// 繋がっていなければ元の木阿弥。
	got := e.EvaluateEvent(map[string]interface{}{
		"type": "process", "process_name": "itest.exe", "agent_id": "a1",
	})
	var fired bool
	for _, m := range got {
		if m.Rule.Name == "ITestCR-on" {
			fired = true
			if m.Rule.AlertTitle != "ITestCR-on fired" {
				t.Errorf("AlertTitle = %q", m.Rule.AlertTitle)
			}
		}
	}
	if !fired {
		t.Error("読み込んだルールが評価で一致しない")
	}
}

// TestLoadFromDB_ReportsQueryFailure はクエリ失敗をエラーとして返すこと。
// ここを握りつぶすと「ルールを作ったのに鳴らない」が静かに再発する。
func TestLoadFromDB_ReportsQueryFailure(t *testing.T) {
	pool := customRulesPool(t)

	// 閉じた ctx でクエリを失敗させる。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := NewCustomRuleEvaluator().LoadFromDB(ctx, pool); err == nil {
		t.Error("クエリ失敗でエラーが返っていない")
	}
}

// TestLoadFromDB_NilPoolIsNoop は pool 未設定で落ちないこと。
func TestLoadFromDB_NilPoolIsNoop(t *testing.T) {
	if err := NewCustomRuleEvaluator().LoadFromDB(context.Background(), nil); err != nil {
		t.Errorf("nil pool でエラー: %v", err)
	}
}
