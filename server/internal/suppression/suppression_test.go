package suppression

import (
	"testing"
	"time"
)

// ─── conditionMatches ─────────────────────────────────────────────────────────

func TestConditionMatches_Eq_CaseInsensitive(t *testing.T) {
	c := Condition{Operator: "eq", Value: "Critical"}
	if !conditionMatches(c, "critical") {
		t.Error("eq: 大文字小文字を区別しない一致が期待されます")
	}
}

func TestConditionMatches_Eq_NoMatch(t *testing.T) {
	c := Condition{Operator: "eq", Value: "high"}
	if conditionMatches(c, "low") {
		t.Error("eq: 異なる値で一致するべきではありません")
	}
}

func TestConditionMatches_Contains(t *testing.T) {
	c := Condition{Operator: "contains", Value: "nessus"}
	if !conditionMatches(c, "host-nessus-01") {
		t.Error("contains: 部分一致が期待されます")
	}
}

func TestConditionMatches_Contains_CaseInsensitive(t *testing.T) {
	c := Condition{Operator: "contains", Value: "NESSUS"}
	if !conditionMatches(c, "host-nessus-01") {
		t.Error("contains: 大文字小文字を無視して一致するべきです")
	}
}

func TestConditionMatches_Contains_NoMatch(t *testing.T) {
	c := Condition{Operator: "contains", Value: "qualys"}
	if conditionMatches(c, "host-nessus-01") {
		t.Error("contains: 含まれない値で一致するべきではありません")
	}
}

func TestConditionMatches_Regex_Match(t *testing.T) {
	c := Condition{Operator: "regex", Value: `^host-\d+$`}
	if !conditionMatches(c, "host-123") {
		t.Error("regex: パターンに一致するはずです")
	}
}

func TestConditionMatches_Regex_NoMatch(t *testing.T) {
	c := Condition{Operator: "regex", Value: `^host-\d+$`}
	if conditionMatches(c, "server-abc") {
		t.Error("regex: パターンに一致しないはずです")
	}
}

func TestConditionMatches_Regex_InvalidPattern(t *testing.T) {
	c := Condition{Operator: "regex", Value: `[invalid`}
	// 不正な正規表現は false を返すべき（パニックしない）
	if conditionMatches(c, "anything") {
		t.Error("不正な正規表現パターンは false を返すべきです")
	}
}

func TestConditionMatches_Lt(t *testing.T) {
	c := Condition{Operator: "lt", Value: "5"}
	if !conditionMatches(c, "3") {
		t.Error("lt: 3 < 5 は true のはずです")
	}
	if conditionMatches(c, "7") {
		t.Error("lt: 7 < 5 は false のはずです")
	}
}

func TestConditionMatches_Lte(t *testing.T) {
	c := Condition{Operator: "lte", Value: "5"}
	if !conditionMatches(c, "5") {
		t.Error("lte: 5 <= 5 は true のはずです")
	}
	if conditionMatches(c, "6") {
		t.Error("lte: 6 <= 5 は false のはずです")
	}
}

func TestConditionMatches_Gt(t *testing.T) {
	c := Condition{Operator: "gt", Value: "5"}
	if !conditionMatches(c, "7") {
		t.Error("gt: 7 > 5 は true のはずです")
	}
	if conditionMatches(c, "3") {
		t.Error("gt: 3 > 5 は false のはずです")
	}
}

func TestConditionMatches_Gte(t *testing.T) {
	c := Condition{Operator: "gte", Value: "5"}
	if !conditionMatches(c, "5") {
		t.Error("gte: 5 >= 5 は true のはずです")
	}
	if conditionMatches(c, "4") {
		t.Error("gte: 4 >= 5 は false のはずです")
	}
}

func TestConditionMatches_UnknownOperator_FallsBackToEq(t *testing.T) {
	c := Condition{Operator: "like", Value: "admin"}
	if !conditionMatches(c, "admin") {
		t.Error("不明なoperatorはeqとして扱われるべきです（一致する場合）")
	}
}

// ─── matchesAll ───────────────────────────────────────────────────────────────

func TestMatchesAll_AllConditionsMatch(t *testing.T) {
	alert := map[string]interface{}{
		"hostname":   "nessus-scanner-01",
		"alert_type": "network",
	}
	conds := []Condition{
		{Field: "hostname", Operator: "contains", Value: "nessus"},
		{Field: "alert_type", Operator: "eq", Value: "network"},
	}
	if !matchesAll(conds, alert) {
		t.Error("全条件が一致する場合 true を返すべきです")
	}
}

func TestMatchesAll_OneConditionFails(t *testing.T) {
	alert := map[string]interface{}{
		"hostname":   "nessus-scanner-01",
		"alert_type": "process", // 一致しない
	}
	conds := []Condition{
		{Field: "hostname", Operator: "contains", Value: "nessus"},
		{Field: "alert_type", Operator: "eq", Value: "network"},
	}
	if matchesAll(conds, alert) {
		t.Error("1条件でも失敗する場合 false を返すべきです")
	}
}

func TestMatchesAll_EmptyConditions_ReturnsFalse(t *testing.T) {
	alert := map[string]interface{}{"hostname": "test"}
	if matchesAll([]Condition{}, alert) {
		t.Error("条件が空の場合 false を返すべきです（誤抑制を防ぐため）")
	}
}

func TestMatchesAll_MissingField_ReturnsFalse(t *testing.T) {
	alert := map[string]interface{}{"hostname": "test"}
	conds := []Condition{
		{Field: "nonexistent_field", Operator: "eq", Value: "value"},
	}
	if matchesAll(conds, alert) {
		t.Error("フィールドが存在しない場合 false を返すべきです")
	}
}

// ─── Engine.ShouldSuppress ────────────────────────────────────────────────────

func newTestEngine() *Engine {
	return &Engine{}
}

func TestShouldSuppress_NoRules(t *testing.T) {
	e := newTestEngine()
	suppressed, _ := e.ShouldSuppress(map[string]interface{}{
		"hostname": "my-server",
	})
	if suppressed {
		t.Error("ルールがない場合、抑制されるべきではありません")
	}
}

func TestShouldSuppress_MatchingRule(t *testing.T) {
	e := newTestEngine()
	e.rules = []*SuppressionRule{
		{
			ID:      "test-rule-1",
			Name:    "Nessus Scanner",
			Enabled: true,
			Conditions: []Condition{
				{Field: "hostname", Operator: "contains", Value: "nessus"},
			},
		},
	}
	suppressed, name := e.ShouldSuppress(map[string]interface{}{
		"hostname": "nessus-prod-01",
	})
	if !suppressed {
		t.Error("一致するルールがある場合、抑制されるべきです")
	}
	if name != "Nessus Scanner" {
		t.Errorf("rule name: got %q, want %q", name, "Nessus Scanner")
	}
}

func TestShouldSuppress_DisabledRuleNotApplied(t *testing.T) {
	e := newTestEngine()
	e.rules = []*SuppressionRule{
		{
			ID:      "disabled-rule",
			Name:    "Disabled",
			Enabled: false, // 無効
			Conditions: []Condition{
				{Field: "hostname", Operator: "eq", Value: "target"},
			},
		},
	}
	suppressed, _ := e.ShouldSuppress(map[string]interface{}{
		"hostname": "target",
	})
	if suppressed {
		t.Error("無効化されたルールは適用されるべきではありません")
	}
}

func TestShouldSuppress_ExpiredRuleNotApplied(t *testing.T) {
	e := newTestEngine()
	past := time.Now().Add(-time.Hour)
	e.rules = []*SuppressionRule{
		{
			ID:        "expired-rule",
			Name:      "Expired",
			Enabled:   true,
			ExpiresAt: &past,
			Conditions: []Condition{
				{Field: "hostname", Operator: "eq", Value: "target"},
			},
		},
	}
	suppressed, _ := e.ShouldSuppress(map[string]interface{}{
		"hostname": "target",
	})
	if suppressed {
		t.Error("期限切れのルールは適用されるべきではありません")
	}
}

func TestShouldSuppress_PermanentRuleAlwaysApplied(t *testing.T) {
	e := newTestEngine()
	e.rules = []*SuppressionRule{
		{
			ID:        "permanent-rule",
			Name:      "Permanent",
			Enabled:   true,
			Duration:  0, // 永続
			ExpiresAt: nil,
			Conditions: []Condition{
				{Field: "process_name", Operator: "contains", Value: "veeam"},
				{Field: "alert_type", Operator: "contains", Value: "file"},
			},
		},
	}
	suppressed, _ := e.ShouldSuppress(map[string]interface{}{
		"process_name": "veeam.exe",
		"alert_type":   "file_access",
	})
	if !suppressed {
		t.Error("永続ルールは常に適用されるべきです")
	}
}

// ─── LoadBuiltinRules ─────────────────────────────────────────────────────────

func TestLoadBuiltinRules_AddsRules(t *testing.T) {
	e := newTestEngine()
	LoadBuiltinRules(e)
	if len(e.rules) == 0 {
		t.Error("LoadBuiltinRulesはルールを追加するべきです")
	}
}

func TestLoadBuiltinRules_NessusRuleWorks(t *testing.T) {
	e := newTestEngine()
	LoadBuiltinRules(e)
	suppressed, name := e.ShouldSuppress(map[string]interface{}{
		"hostname": "nessus-scanner.corp",
	})
	if !suppressed {
		t.Error("組み込みNessusルールでhostnameにnessusを含むアラートは抑制されるべきです")
	}
	_ = name
}
