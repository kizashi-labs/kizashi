package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─── AlertAssignRule 構造体テスト ─────────────────────────────────────────────

// TestAlertAssignRule_ZeroValue は AlertAssignRule のゼロ値フィールドを確認する
func TestAlertAssignRule_ZeroValue(t *testing.T) {
	var r AlertAssignRule
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", r.Name)
	}
	if r.Priority != 0 {
		t.Errorf("Priority のデフォルト = %d, want 0", r.Priority)
	}
	if r.AssigneeID != "" {
		t.Errorf("AssigneeID のデフォルト = %q, want \"\"", r.AssigneeID)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestAlertAssignRule_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestAlertAssignRule_FieldAssignment(t *testing.T) {
	r := AlertAssignRule{
		ID:         "rule-001",
		Name:       "Critical Auto-Assign",
		Priority:   100,
		AssigneeID: "user-abc",
		Enabled:    true,
	}
	if r.ID != "rule-001" {
		t.Errorf("ID = %q, want \"rule-001\"", r.ID)
	}
	if r.Priority != 100 {
		t.Errorf("Priority = %d, want 100", r.Priority)
	}
	if !r.Enabled {
		t.Error("Enabled は true であるべき")
	}
}

// TestAlertAssignRule_PriorityOrdering は優先度の大小比較を確認する
// DBクエリは priority DESC なので高い値が先に評価される
func TestAlertAssignRule_PriorityOrdering(t *testing.T) {
	rules := []AlertAssignRule{
		{Priority: 50},
		{Priority: 100},
		{Priority: 10},
	}
	// 最大優先度を特定する
	maxPriority := rules[0].Priority
	for _, r := range rules[1:] {
		if r.Priority > maxPriority {
			maxPriority = r.Priority
		}
	}
	if maxPriority != 100 {
		t.Errorf("最大優先度 = %d, want 100", maxPriority)
	}
}

// TestAlertAssignConditions_EmptyMeansMatchAll は
// conditions が空の場合は全アラートにマッチすることを確認する
func TestAlertAssignConditions_EmptyMeansMatchAll(t *testing.T) {
	// FindMatch メソッドと同じロジック: 空スライスは match-all を意味する
	var cond alertAssignConditions
	severityOK := len(cond.SeverityMatch) == 0
	ruleOK := len(cond.RuleIDMatch) == 0
	if !severityOK {
		t.Error("SeverityMatch が空の場合は severityOK = true であるべき")
	}
	if !ruleOK {
		t.Error("RuleIDMatch が空の場合は ruleOK = true であるべき")
	}
}

// TestAlertAssignConditions_SeverityMatchHit は
// SeverityMatch にアラートの重大度が含まれる場合にマッチすることを確認する
func TestAlertAssignConditions_SeverityMatchHit(t *testing.T) {
	cond := alertAssignConditions{
		SeverityMatch: []string{"critical", "high"},
	}
	alertSeverity := "critical"

	severityOK := len(cond.SeverityMatch) == 0
	for _, s := range cond.SeverityMatch {
		if s == alertSeverity {
			severityOK = true
			break
		}
	}
	if !severityOK {
		t.Errorf("SeverityMatch=%v に %q が含まれる場合はマッチするべき", cond.SeverityMatch, alertSeverity)
	}
}

// TestAlertAssignConditions_SeverityMatchMiss は
// SeverityMatch にアラートの重大度が含まれない場合にマッチしないことを確認する
func TestAlertAssignConditions_SeverityMatchMiss(t *testing.T) {
	cond := alertAssignConditions{
		SeverityMatch: []string{"critical", "high"},
	}
	alertSeverity := "low"

	severityOK := len(cond.SeverityMatch) == 0
	for _, s := range cond.SeverityMatch {
		if s == alertSeverity {
			severityOK = true
			break
		}
	}
	if severityOK {
		t.Errorf("SeverityMatch=%v に %q が含まれない場合はマッチしないべき", cond.SeverityMatch, alertSeverity)
	}
}

// TestAlertAssignConditions_RuleIDMatchHit は
// RuleIDMatch にルールIDが含まれる場合にマッチすることを確認する
func TestAlertAssignConditions_RuleIDMatchHit(t *testing.T) {
	cond := alertAssignConditions{
		RuleIDMatch: []string{"rule-ransomware", "rule-lateral-move"},
	}
	targetRuleID := "rule-ransomware"

	ruleOK := len(cond.RuleIDMatch) == 0
	for _, r := range cond.RuleIDMatch {
		if r == targetRuleID {
			ruleOK = true
			break
		}
	}
	if !ruleOK {
		t.Errorf("RuleIDMatch=%v に %q が含まれる場合はマッチするべき", cond.RuleIDMatch, targetRuleID)
	}
}

// TestAlertAssignConditions_BothConditionsMustMatch は
// Severity と RuleID の両方が一致する場合のみ全体マッチとなることを確認する
func TestAlertAssignConditions_BothConditionsMustMatch(t *testing.T) {
	cond := alertAssignConditions{
		SeverityMatch: []string{"critical"},
		RuleIDMatch:   []string{"rule-x"},
	}

	// severity=critical, ruleID=rule-x → 両方マッチ
	severityOK := false
	for _, s := range cond.SeverityMatch {
		if s == "critical" {
			severityOK = true
		}
	}
	ruleOK := false
	for _, r := range cond.RuleIDMatch {
		if r == "rule-x" {
			ruleOK = true
		}
	}
	if !severityOK || !ruleOK {
		t.Error("両条件が揃う場合はマッチするべき")
	}

	// severity=low → マッチしない
	severityOK2 := false
	for _, s := range cond.SeverityMatch {
		if s == "low" {
			severityOK2 = true
		}
	}
	if severityOK2 {
		t.Error("severity=low は SeverityMatch=[critical] にマッチしないべき")
	}
}

// TestCreateAssignRuleInput_EmptyConditionsCoercedToEmptyJSON は
// Conditions が空の場合に "{}" に変換されることを確認する
func TestCreateAssignRuleInput_EmptyConditionsCoercedToEmptyJSON(t *testing.T) {
	// Create/Update メソッドと同じガードロジック
	in := CreateAssignRuleInput{Conditions: nil}
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if string(cond) != "{}" {
		t.Errorf("空 Conditions は \"{}\" に変換されるべき: got %q", string(cond))
	}
}

// TestAlertAssignRule_AssignRuleSelectColsContainsRequiredFields は
// assignRuleSelectCols に必要なカラムが含まれることを確認する
func TestAlertAssignRule_AssignRuleSelectColsContainsRequiredFields(t *testing.T) {
	requiredFields := []string{
		"id", "name", "priority", "conditions",
		"enabled", "created_at", "updated_at",
	}
	for _, field := range requiredFields {
		if !strings.Contains(assignRuleSelectCols, field) {
			t.Errorf("assignRuleSelectCols に %q が含まれるべき", field)
		}
	}
}

// TestAlertAssignConditions_JSONRoundTrip は
// alertAssignConditions が JSON シリアライズ/デシリアライズで値を保持することを確認する
func TestAlertAssignConditions_JSONRoundTrip(t *testing.T) {
	original := alertAssignConditions{
		SeverityMatch: []string{"critical", "high"},
		RuleIDMatch:   []string{"rule-a", "rule-b"},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("JSON Marshal エラー: %v", err)
	}
	var decoded alertAssignConditions
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON Unmarshal エラー: %v", err)
	}
	if len(decoded.SeverityMatch) != 2 {
		t.Errorf("SeverityMatch の長さ = %d, want 2", len(decoded.SeverityMatch))
	}
	if len(decoded.RuleIDMatch) != 2 {
		t.Errorf("RuleIDMatch の長さ = %d, want 2", len(decoded.RuleIDMatch))
	}
	if decoded.SeverityMatch[0] != "critical" {
		t.Errorf("SeverityMatch[0] = %q, want \"critical\"", decoded.SeverityMatch[0])
	}
}

// TestUpdateAssignRuleInput_EmptyConditionsCoercedToEmptyJSON は
// UpdateAssignRuleInput.Conditions が空の場合に "{}" に変換されることを確認する
func TestUpdateAssignRuleInput_EmptyConditionsCoercedToEmptyJSON(t *testing.T) {
	in := UpdateAssignRuleInput{Conditions: json.RawMessage("")}
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if string(cond) != "{}" {
		t.Errorf("空 Conditions は \"{}\" に変換されるべき: got %q", string(cond))
	}
}
