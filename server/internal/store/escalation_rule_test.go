package store

import (
	"testing"
	"time"
)

// ─── エスカレーションルール純粋関数ヘルパー ───────────────────────────────────

// ruleTriggersForSeverity はルールが指定の重大度アラートに対してトリガーするか判定する
// ルールが有効かつ severity_min <= alertSeverity の場合にトリガーする
func ruleTriggersForSeverity(r *EscalationRule, alertSeverity int16) bool {
	return r.Enabled && r.SeverityMin <= alertSeverity
}

// ruleTriggersForUnresolvedTime はアラートが未解決分数に達した場合にルールがトリガーするか判定する
func ruleTriggersForUnresolvedTime(r *EscalationRule, unresolvedMins int) bool {
	return r.Enabled && unresolvedMins >= r.UnresolvedMins
}

// filterEnabledRules は有効なルールのみを返す
func filterEnabledRules(rules []*EscalationRule) []*EscalationRule {
	var result []*EscalationRule
	for _, r := range rules {
		if r.Enabled {
			result = append(result, r)
		}
	}
	if result == nil {
		result = []*EscalationRule{}
	}
	return result
}

// filterRulesForSeverity は severity_min <= threshold のルールを返す
func filterRulesForSeverity(rules []*EscalationRule, threshold int16) []*EscalationRule {
	var result []*EscalationRule
	for _, r := range rules {
		if r.SeverityMin <= threshold {
			result = append(result, r)
		}
	}
	if result == nil {
		result = []*EscalationRule{}
	}
	return result
}

// ─── EscalationRule 構造体テスト ─────────────────────────────────────────────

// TestEscalationRule_DefaultValues は EscalationRule のゼロ値フィールドを確認する
func TestEscalationRule_DefaultValues(t *testing.T) {
	var r EscalationRule
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.SeverityMin != 0 {
		t.Errorf("SeverityMin のデフォルト = %d, want 0", r.SeverityMin)
	}
	if r.UnresolvedMins != 0 {
		t.Errorf("UnresolvedMins のデフォルト = %d, want 0", r.UnresolvedMins)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestEscalationRule_FieldAssignment はフィールドへの代入が正しく反映されることを確認する
func TestEscalationRule_FieldAssignment(t *testing.T) {
	ch := "slack"
	r := EscalationRule{
		ID:             "rule-001",
		Name:           "高重大度エスカレーション",
		SeverityMin:    7,
		UnresolvedMins: 30,
		EscalateTo:     "security-team",
		NotifyChannel:  &ch,
		Enabled:        true,
		CreatedAt:      time.Now().Format(time.RFC3339),
	}
	if r.ID != "rule-001" {
		t.Errorf("ID = %q, want \"rule-001\"", r.ID)
	}
	if r.SeverityMin != 7 {
		t.Errorf("SeverityMin = %d, want 7", r.SeverityMin)
	}
	if r.UnresolvedMins != 30 {
		t.Errorf("UnresolvedMins = %d, want 30", r.UnresolvedMins)
	}
	if r.NotifyChannel == nil || *r.NotifyChannel != "slack" {
		t.Errorf("NotifyChannel = %v, want \"slack\"", r.NotifyChannel)
	}
}

// TestRuleTriggersForSeverity_Enabled_AboveMin は有効ルールが severity_min 以上のアラートでトリガーすることを確認する
func TestRuleTriggersForSeverity_Enabled_AboveMin(t *testing.T) {
	r := &EscalationRule{SeverityMin: 5, Enabled: true}
	// severity 7 は severity_min 5 以上なのでトリガーすべき
	if !ruleTriggersForSeverity(r, 7) {
		t.Error("severity 7 のアラートは severity_min 5 のルールをトリガーすべき")
	}
}

// TestRuleTriggersForSeverity_Enabled_ExactMin は severity_min ぴったりでもトリガーすることを確認する
func TestRuleTriggersForSeverity_Enabled_ExactMin(t *testing.T) {
	r := &EscalationRule{SeverityMin: 5, Enabled: true}
	if !ruleTriggersForSeverity(r, 5) {
		t.Error("severity_min と同じ重大度でもトリガーすべき")
	}
}

// TestRuleTriggersForSeverity_Enabled_BelowMin は重大度が severity_min 未満のアラートではトリガーしないことを確認する
func TestRuleTriggersForSeverity_Enabled_BelowMin(t *testing.T) {
	r := &EscalationRule{SeverityMin: 8, Enabled: true}
	// severity 3 は severity_min 8 未満なのでトリガーしない
	if ruleTriggersForSeverity(r, 3) {
		t.Error("severity 3 のアラートは severity_min 8 のルールをトリガーすべきでない")
	}
}

// TestRuleTriggersForSeverity_Disabled_NeverTriggers は無効ルールがどの重大度でもトリガーしないことを確認する
func TestRuleTriggersForSeverity_Disabled_NeverTriggers(t *testing.T) {
	r := &EscalationRule{SeverityMin: 1, Enabled: false}
	// Enabled=false なので重大度に関わらずトリガーしない
	for _, sev := range []int16{1, 5, 10} {
		if ruleTriggersForSeverity(r, sev) {
			t.Errorf("無効ルールは severity %d でトリガーすべきでない", sev)
		}
	}
}

// TestRuleTriggersForUnresolvedTime_AboveThreshold は未解決時間が閾値以上でトリガーすることを確認する
func TestRuleTriggersForUnresolvedTime_AboveThreshold(t *testing.T) {
	r := &EscalationRule{UnresolvedMins: 30, Enabled: true}
	// 45分間未解決 → トリガーすべき
	if !ruleTriggersForUnresolvedTime(r, 45) {
		t.Error("45分未解決は30分閾値のルールをトリガーすべき")
	}
}

// TestRuleTriggersForUnresolvedTime_ExactThreshold は閾値ぴったりでトリガーすることを確認する
func TestRuleTriggersForUnresolvedTime_ExactThreshold(t *testing.T) {
	r := &EscalationRule{UnresolvedMins: 60, Enabled: true}
	if !ruleTriggersForUnresolvedTime(r, 60) {
		t.Error("未解決時間が閾値ちょうどでもトリガーすべき")
	}
}

// TestRuleTriggersForUnresolvedTime_BelowThreshold は閾値未満では未トリガーであることを確認する
func TestRuleTriggersForUnresolvedTime_BelowThreshold(t *testing.T) {
	r := &EscalationRule{UnresolvedMins: 60, Enabled: true}
	if ruleTriggersForUnresolvedTime(r, 30) {
		t.Error("30分未解決は60分閾値のルールをトリガーすべきでない")
	}
}

// TestFilterEnabledRules_MixedRules は有効・無効ルール混在リストから有効のみ抽出できることを確認する
func TestFilterEnabledRules_MixedRules(t *testing.T) {
	rules := []*EscalationRule{
		{ID: "r1", Enabled: true},
		{ID: "r2", Enabled: false},
		{ID: "r3", Enabled: true},
		{ID: "r4", Enabled: false},
	}
	enabled := filterEnabledRules(rules)
	if len(enabled) != 2 {
		t.Errorf("有効ルール数 = %d, want 2", len(enabled))
	}
	for _, r := range enabled {
		if !r.Enabled {
			t.Errorf("無効ルール %q がフィルタ結果に含まれている", r.ID)
		}
	}
}

// TestFilterEnabledRules_EmptySlice は空スライスに対して空スライスを返すことを確認する
func TestFilterEnabledRules_EmptySlice(t *testing.T) {
	result := filterEnabledRules([]*EscalationRule{})
	if len(result) != 0 {
		t.Errorf("空入力から空出力のはず: got %d items", len(result))
	}
}

// TestFilterRulesForSeverity_FiltersCorrectly は重大度フィルタが正しく機能することを確認する
func TestFilterRulesForSeverity_FiltersCorrectly(t *testing.T) {
	rules := []*EscalationRule{
		{ID: "r1", SeverityMin: 3},
		{ID: "r2", SeverityMin: 7},
		{ID: "r3", SeverityMin: 5},
		{ID: "r4", SeverityMin: 9},
	}
	// threshold 6: SeverityMin <= 6 のルールは r1(3), r3(5)
	result := filterRulesForSeverity(rules, 6)
	if len(result) != 2 {
		t.Errorf("重大度フィルタ結果 = %d, want 2", len(result))
	}
}

// TestEscalationRule_NotifyChannel_Optional は NotifyChannel が省略可能なことを確認する
func TestEscalationRule_NotifyChannel_Optional(t *testing.T) {
	r := EscalationRule{
		ID:         "rule-no-channel",
		Name:       "チャンネルなしルール",
		EscalateTo: "manager",
		Enabled:    true,
		// NotifyChannel は nil のまま
	}
	if r.NotifyChannel != nil {
		t.Errorf("NotifyChannel が設定されていない場合は nil であるべき: got %v", r.NotifyChannel)
	}
}

// TestCreateEscalationRuleInput_FieldAssignment は CreateEscalationRuleInput のフィールド代入を確認する
func TestCreateEscalationRuleInput_FieldAssignment(t *testing.T) {
	ch := "teams"
	input := CreateEscalationRuleInput{
		Name:           "クリティカルルール",
		SeverityMin:    9,
		UnresolvedMins: 15,
		EscalateTo:     "ciso",
		NotifyChannel:  &ch,
		Enabled:        true,
	}
	if input.SeverityMin != 9 {
		t.Errorf("SeverityMin = %d, want 9", input.SeverityMin)
	}
	if input.UnresolvedMins != 15 {
		t.Errorf("UnresolvedMins = %d, want 15", input.UnresolvedMins)
	}
	if input.NotifyChannel == nil || *input.NotifyChannel != "teams" {
		t.Errorf("NotifyChannel = %v, want \"teams\"", input.NotifyChannel)
	}
}
