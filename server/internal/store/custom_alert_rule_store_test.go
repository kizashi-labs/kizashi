package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─── カスタムアラートルール条件評価ヘルパー ──────────────────────────────────

// validConditionOperators は使用可能な条件演算子の一覧を返す
func validConditionOperators() []string {
	return []string{
		"equals",
		"not_equals",
		"contains",
		"not_contains",
		"starts_with",
		"ends_with",
		"regex",
		"gt",
		"gte",
		"lt",
		"lte",
	}
}

// isValidConditionOperator は演算子が有効かどうかを判定する
func isValidConditionOperator(op string) bool {
	for _, v := range validConditionOperators() {
		if v == op {
			return true
		}
	}
	return false
}

// isValidEventType はイベントタイプが既知の値かどうかを判定する
func isValidEventType(eventType string) bool {
	switch eventType {
	case "process", "network", "file", "registry", "dns", "alert", "login":
		return true
	}
	return false
}

// isValidRuleSeverity はカスタムアラートルールの重大度が 1〜10 の範囲か確認する
func isValidRuleSeverity(severity int) bool {
	return severity >= 1 && severity <= 10
}

// isValidTimeWindow は時間ウィンドウ（秒）が正の値かどうかを確認する
func isValidTimeWindow(seconds int) bool {
	return seconds > 0
}

// isValidThresholdCount はしきい値カウントが正の整数かどうかを確認する
func isValidThresholdCount(count int) bool {
	return count >= 1
}

// conditionIsComplete は Condition の全必須フィールドが設定されているか確認する
func conditionIsComplete(c Condition) bool {
	return c.Field != "" && c.Operator != "" && c.Value != ""
}

// parseConditions は JSON の条件配列を []Condition にデコードする純粋ヘルパー
func parseConditions(raw json.RawMessage) ([]Condition, error) {
	if len(raw) == 0 {
		return []Condition{}, nil
	}
	var conds []Condition
	if err := json.Unmarshal(raw, &conds); err != nil {
		return nil, err
	}
	return conds, nil
}

// filterValidConditions は完全な条件のみを返す
func filterValidConditions(conds []Condition) []Condition {
	var result []Condition
	for _, c := range conds {
		if conditionIsComplete(c) {
			result = append(result, c)
		}
	}
	if result == nil {
		result = []Condition{}
	}
	return result
}

// customAlertRuleMatchesSeverity はルールの Severity が指定の閾値以上か確認する
func customAlertRuleMatchesSeverity(r *CustomAlertRule, minSeverity int) bool {
	return r.Severity >= minSeverity
}

// ─── Condition 構造体テスト ───────────────────────────────────────────────────

// TestCondition_ZeroValue は Condition のゼロ値が期待通りであることを確認する
func TestCondition_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルトが空文字であることを確認する
	var c Condition
	if c.Field != "" {
		t.Errorf("Field のデフォルト = %q, want \"\"", c.Field)
	}
	if c.Operator != "" {
		t.Errorf("Operator のデフォルト = %q, want \"\"", c.Operator)
	}
	if c.Value != "" {
		t.Errorf("Value のデフォルト = %q, want \"\"", c.Value)
	}
}

// TestCondition_FieldAssignment は Condition フィールドへの代入を確認する
func TestCondition_FieldAssignment(t *testing.T) {
	// フィールド代入が正しく反映されるか確認する
	c := Condition{
		Field:    "process.name",
		Operator: "equals",
		Value:    "powershell.exe",
	}
	if c.Field != "process.name" {
		t.Errorf("Field = %q, want \"process.name\"", c.Field)
	}
	if c.Operator != "equals" {
		t.Errorf("Operator = %q, want \"equals\"", c.Operator)
	}
	if c.Value != "powershell.exe" {
		t.Errorf("Value = %q, want \"powershell.exe\"", c.Value)
	}
}

// TestIsValidConditionOperator_ValidOperators は有効な演算子が受け入れられることを確認する
func TestIsValidConditionOperator_ValidOperators(t *testing.T) {
	// 全ての定義済み演算子が有効と判定されるか確認する
	for _, op := range validConditionOperators() {
		if !isValidConditionOperator(op) {
			t.Errorf("有効な演算子 %q が無効と判定された", op)
		}
	}
}

// TestIsValidConditionOperator_InvalidOperators は無効な演算子が拒否されることを確認する
func TestIsValidConditionOperator_InvalidOperators(t *testing.T) {
	// 未定義の演算子は拒否される
	invalidOps := []string{"EQUALS", "like", "!=", "==", "", "match"}
	for _, op := range invalidOps {
		if isValidConditionOperator(op) {
			t.Errorf("無効な演算子 %q が有効と判定された", op)
		}
	}
}

// TestIsValidEventType_ValidTypes は有効なイベントタイプを確認する
func TestIsValidEventType_ValidTypes(t *testing.T) {
	// 既知のイベントタイプが全て有効と判定されるか確認する
	validTypes := []string{"process", "network", "file", "registry", "dns", "alert", "login"}
	for _, et := range validTypes {
		if !isValidEventType(et) {
			t.Errorf("有効なイベントタイプ %q が無効と判定された", et)
		}
	}
}

// TestIsValidEventType_InvalidTypes は無効なイベントタイプが拒否されることを確認する
func TestIsValidEventType_InvalidTypes(t *testing.T) {
	// 未定義のイベントタイプは拒否される
	invalidTypes := []string{"Process", "NETWORK", "kernel", "", "log", "syscall"}
	for _, et := range invalidTypes {
		if isValidEventType(et) {
			t.Errorf("無効なイベントタイプ %q が有効と判定された", et)
		}
	}
}

// TestIsValidRuleSeverity_ValidRange は重大度 1〜10 の範囲を確認する
func TestIsValidRuleSeverity_ValidRange(t *testing.T) {
	// 1から10の全ての値が有効か確認する
	for sev := 1; sev <= 10; sev++ {
		if !isValidRuleSeverity(sev) {
			t.Errorf("重大度 %d は有効であるべき", sev)
		}
	}
}

// TestIsValidRuleSeverity_OutOfRange は範囲外の重大度が無効と判定されることを確認する
func TestIsValidRuleSeverity_OutOfRange(t *testing.T) {
	// 0以下と11以上は無効
	invalidCases := []int{0, -1, 11, 100}
	for _, sev := range invalidCases {
		if isValidRuleSeverity(sev) {
			t.Errorf("重大度 %d は無効であるべき", sev)
		}
	}
}

// TestIsValidTimeWindow_PositiveValues は正の時間ウィンドウが有効であることを確認する
func TestIsValidTimeWindow_PositiveValues(t *testing.T) {
	// 1秒以上は全て有効
	validCases := []int{1, 60, 300, 3600, 86400}
	for _, tw := range validCases {
		if !isValidTimeWindow(tw) {
			t.Errorf("時間ウィンドウ %d 秒は有効であるべき", tw)
		}
	}
}

// TestIsValidTimeWindow_ZeroOrNegative はゼロ以下の時間ウィンドウが無効であることを確認する
func TestIsValidTimeWindow_ZeroOrNegative(t *testing.T) {
	// 0以下は無効
	invalidCases := []int{0, -1, -300}
	for _, tw := range invalidCases {
		if isValidTimeWindow(tw) {
			t.Errorf("時間ウィンドウ %d 秒は無効であるべき", tw)
		}
	}
}

// TestIsValidThresholdCount_ValidCounts は有効なしきい値カウントを確認する
func TestIsValidThresholdCount_ValidCounts(t *testing.T) {
	// 1以上は全て有効
	validCases := []int{1, 5, 10, 100, 1000}
	for _, count := range validCases {
		if !isValidThresholdCount(count) {
			t.Errorf("しきい値カウント %d は有効であるべき", count)
		}
	}
}

// TestIsValidThresholdCount_ZeroOrNegative はゼロ以下のしきい値カウントが無効であることを確認する
func TestIsValidThresholdCount_ZeroOrNegative(t *testing.T) {
	// 0以下は無効
	invalidCases := []int{0, -1, -100}
	for _, count := range invalidCases {
		if isValidThresholdCount(count) {
			t.Errorf("しきい値カウント %d は無効であるべき", count)
		}
	}
}

// TestConditionIsComplete_AllFields は全フィールドが設定された Condition が完全であることを確認する
func TestConditionIsComplete_AllFields(t *testing.T) {
	// 全フィールドが設定されていれば完全
	c := Condition{Field: "file.path", Operator: "contains", Value: "/tmp/"}
	if !conditionIsComplete(c) {
		t.Error("全フィールドが設定された Condition は完全であるべき")
	}
}

// TestConditionIsComplete_MissingField は Field が空の場合に不完全と判定されることを確認する
func TestConditionIsComplete_MissingField(t *testing.T) {
	// Field が空は不完全
	c := Condition{Field: "", Operator: "equals", Value: "malware.exe"}
	if conditionIsComplete(c) {
		t.Error("Field が空の Condition は不完全であるべき")
	}
}

// TestConditionIsComplete_MissingOperator は Operator が空の場合に不完全と判定されることを確認する
func TestConditionIsComplete_MissingOperator(t *testing.T) {
	// Operator が空は不完全
	c := Condition{Field: "process.name", Operator: "", Value: "cmd.exe"}
	if conditionIsComplete(c) {
		t.Error("Operator が空の Condition は不完全であるべき")
	}
}

// TestConditionIsComplete_MissingValue は Value が空の場合に不完全と判定されることを確認する
func TestConditionIsComplete_MissingValue(t *testing.T) {
	// Value が空は不完全
	c := Condition{Field: "network.dst_ip", Operator: "equals", Value: ""}
	if conditionIsComplete(c) {
		t.Error("Value が空の Condition は不完全であるべき")
	}
}

// TestParseConditions_ValidJSON は有効な JSON 条件配列をデコードできることを確認する
func TestParseConditions_ValidJSON(t *testing.T) {
	// 有効な JSON 配列が正しくデコードされるか確認する
	raw := json.RawMessage(`[{"field":"process.name","operator":"equals","value":"mimikatz.exe"}]`)
	conds, err := parseConditions(raw)
	if err != nil {
		t.Fatalf("parseConditions エラー: %v", err)
	}
	if len(conds) != 1 {
		t.Fatalf("条件数 = %d, want 1", len(conds))
	}
	if conds[0].Field != "process.name" {
		t.Errorf("Field = %q, want \"process.name\"", conds[0].Field)
	}
	if conds[0].Operator != "equals" {
		t.Errorf("Operator = %q, want \"equals\"", conds[0].Operator)
	}
	if conds[0].Value != "mimikatz.exe" {
		t.Errorf("Value = %q, want \"mimikatz.exe\"", conds[0].Value)
	}
}

// TestParseConditions_EmptyRaw は空の RawMessage が空スライスを返すことを確認する
func TestParseConditions_EmptyRaw(t *testing.T) {
	// 空の RawMessage はエラーなく空スライスを返す
	conds, err := parseConditions(json.RawMessage{})
	if err != nil {
		t.Fatalf("空 RawMessage でエラー: %v", err)
	}
	if len(conds) != 0 {
		t.Errorf("空 RawMessage の条件数 = %d, want 0", len(conds))
	}
}

// TestParseConditions_MultipleConditions は複数条件のデコードを確認する
func TestParseConditions_MultipleConditions(t *testing.T) {
	// 複数の条件が正しくデコードされるか確認する
	raw := json.RawMessage(`[
		{"field":"process.name","operator":"contains","value":"powershell"},
		{"field":"network.dst_port","operator":"equals","value":"4444"},
		{"field":"file.path","operator":"starts_with","value":"C:\\\\Temp"}
	]`)
	conds, err := parseConditions(raw)
	if err != nil {
		t.Fatalf("parseConditions エラー: %v", err)
	}
	if len(conds) != 3 {
		t.Errorf("条件数 = %d, want 3", len(conds))
	}
}

// TestFilterValidConditions_FiltersIncomplete は不完全な条件が除去されることを確認する
func TestFilterValidConditions_FiltersIncomplete(t *testing.T) {
	// 完全な条件と不完全な条件が混在する場合、完全なもののみが残る
	conds := []Condition{
		{Field: "process.name", Operator: "equals", Value: "cmd.exe"},
		{Field: "", Operator: "equals", Value: "something"},
		{Field: "file.path", Operator: "contains", Value: "/tmp/"},
		{Field: "dns.query", Operator: "", Value: "evil.com"},
	}
	valid := filterValidConditions(conds)
	if len(valid) != 2 {
		t.Errorf("有効な条件数 = %d, want 2", len(valid))
	}
}

// TestCustomAlertRule_ZeroValue は CustomAlertRule のゼロ値を確認する
func TestCustomAlertRule_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルト値を確認する
	var r CustomAlertRule
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if r.ThresholdCount != 0 {
		t.Errorf("ThresholdCount のデフォルト = %d, want 0", r.ThresholdCount)
	}
	if r.TimeWindowSeconds != 0 {
		t.Errorf("TimeWindowSeconds のデフォルト = %d, want 0", r.TimeWindowSeconds)
	}
	if r.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", r.Severity)
	}
	if r.CreatedBy != nil {
		t.Error("CreatedBy のデフォルトは nil であるべき")
	}
}

// TestCustomAlertRule_FieldAssignment は CustomAlertRule フィールド代入を確認する
func TestCustomAlertRule_FieldAssignment(t *testing.T) {
	// 全フィールドへの代入が正しく反映されるか確認する
	createdBy := "admin-user-001"
	conds := json.RawMessage(`[{"field":"process.name","operator":"equals","value":"nc.exe"}]`)
	mitreTags := []string{"T1059", "T1021"}
	r := CustomAlertRule{
		ID:                "rule-001",
		Name:              "ネットキャット検出",
		Description:       "nc.exe の実行を検出する",
		Enabled:           true,
		EventType:         "process",
		Conditions:        conds,
		ThresholdCount:    3,
		TimeWindowSeconds: 300,
		Severity:          8,
		AlertTitle:        "ネットキャット実行を検出",
		AlertDescription:  "攻撃者がネットキャットを使用している可能性があります",
		MitreTags:         mitreTags,
		CreatedBy:         &createdBy,
	}

	if r.Name != "ネットキャット検出" {
		t.Errorf("Name = %q, want \"ネットキャット検出\"", r.Name)
	}
	if r.ThresholdCount != 3 {
		t.Errorf("ThresholdCount = %d, want 3", r.ThresholdCount)
	}
	if r.TimeWindowSeconds != 300 {
		t.Errorf("TimeWindowSeconds = %d, want 300", r.TimeWindowSeconds)
	}
	if len(r.MitreTags) != 2 {
		t.Errorf("MitreTags の長さ = %d, want 2", len(r.MitreTags))
	}
	if r.CreatedBy == nil || *r.CreatedBy != createdBy {
		t.Errorf("CreatedBy = %v, want %q", r.CreatedBy, createdBy)
	}
}

// TestCustomAlertRuleMatchesSeverity_AboveMin は重大度がしきい値以上の場合にマッチすることを確認する
func TestCustomAlertRuleMatchesSeverity_AboveMin(t *testing.T) {
	// Severity 8 のルールは minSeverity 5 でマッチする
	r := &CustomAlertRule{Severity: 8}
	if !customAlertRuleMatchesSeverity(r, 5) {
		t.Error("Severity 8 は minSeverity 5 にマッチすべき")
	}
}

// TestCustomAlertRuleMatchesSeverity_ExactMatch は重大度がしきい値と等しい場合にマッチすることを確認する
func TestCustomAlertRuleMatchesSeverity_ExactMatch(t *testing.T) {
	// Severity 7 と minSeverity 7 は等しいのでマッチする
	r := &CustomAlertRule{Severity: 7}
	if !customAlertRuleMatchesSeverity(r, 7) {
		t.Error("Severity 7 は minSeverity 7 にマッチすべき")
	}
}

// TestCustomAlertRuleMatchesSeverity_BelowMin は重大度がしきい値未満の場合にマッチしないことを確認する
func TestCustomAlertRuleMatchesSeverity_BelowMin(t *testing.T) {
	// Severity 3 は minSeverity 5 にマッチしない
	r := &CustomAlertRule{Severity: 3}
	if customAlertRuleMatchesSeverity(r, 5) {
		t.Error("Severity 3 は minSeverity 5 にマッチすべきでない")
	}
}

// TestCustomAlertRule_MitreTagsDefaultEmpty は MitreTags のデフォルトが空スライスになることを確認する
func TestCustomAlertRule_MitreTagsDefaultEmpty(t *testing.T) {
	// MitreTags を明示的に空スライスに設定した場合の確認
	r := CustomAlertRule{
		Name:      "タグなしルール",
		MitreTags: []string{},
	}
	if r.MitreTags == nil {
		t.Error("MitreTags は nil でなく空スライスであるべき")
	}
	if len(r.MitreTags) != 0 {
		t.Errorf("MitreTags の長さ = %d, want 0", len(r.MitreTags))
	}
}

// TestCustomAlertRuleSelectCols_ContainsRequiredColumns は SELECT カラム定数を確認する
func TestCustomAlertRuleSelectCols_ContainsRequiredColumns(t *testing.T) {
	// customAlertRuleSelectCols が必須カラムを含むか検証する
	requiredCols := []string{
		"conditions", "threshold_count", "time_window_seconds",
		"severity", "alert_title", "mitre_tags",
	}
	for _, col := range requiredCols {
		if !strings.Contains(customAlertRuleSelectCols, col) {
			t.Errorf("SELECT カラム定数に %q が含まれていない", col)
		}
	}
}
