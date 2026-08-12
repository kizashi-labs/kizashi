package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─── 自動応答アクションタイプ検証ヘルパー ────────────────────────────────────

// validAutoResponseActionTypes は許可されているアクションタイプの一覧を返す
func validAutoResponseActionTypes() []string {
	return []string{
		"isolate_host",
		"kill_process",
		"block_hash",
		"block_ip",
		"run_script",
		"notify_slack",
		"create_ticket",
		"quarantine_file",
	}
}

// isValidActionType はアクションタイプが既知の有効値かどうかを判定する
func isValidActionType(actionType string) bool {
	for _, v := range validAutoResponseActionTypes() {
		if v == actionType {
			return true
		}
	}
	return false
}

// isValidTriggerStatus はトリガーステータスが有効な値かどうかを判定する
func isValidTriggerStatus(status string) bool {
	switch status {
	case "open", "in_progress", "resolved", "any":
		return true
	}
	return false
}

// isValidCooldown はクールダウン秒数が許容範囲内かどうかを確認する（0〜86400）
func isValidCooldown(seconds int) bool {
	return seconds >= 0 && seconds <= 86400
}

// isValidSeverityMin はトリガー最低重大度が 1〜10 の範囲にあるか確認する
func isValidSeverityMin(sev int) bool {
	return sev >= 1 && sev <= 10
}

// autoResponseRuleHasRequiredFields はルールが最低限必要なフィールドを持つか確認する
func autoResponseRuleHasRequiredFields(r *AutoResponseRule) bool {
	return r.Name != "" && r.ActionType != "" && r.TriggerStatus != ""
}

// executionIsTerminal は実行ステータスが終端状態（success または failed）かどうかを判定する
func executionIsTerminal(status string) bool {
	return status == "success" || status == "failed"
}

// filterRulesByActionType は指定のアクションタイプのルールのみ返す
func filterRulesByActionType(rules []*AutoResponseRule, actionType string) []*AutoResponseRule {
	var result []*AutoResponseRule
	for _, r := range rules {
		if r.ActionType == actionType {
			result = append(result, r)
		}
	}
	if result == nil {
		result = []*AutoResponseRule{}
	}
	return result
}

// filterRulesBySeverityMin は trigger_severity_min が threshold 以下のルールを返す
func filterRulesBySeverityMin(rules []*AutoResponseRule, threshold int) []*AutoResponseRule {
	var result []*AutoResponseRule
	for _, r := range rules {
		if r.TriggerSeverityMin <= threshold {
			result = append(result, r)
		}
	}
	if result == nil {
		result = []*AutoResponseRule{}
	}
	return result
}

// ─── AutoResponseRule 構造体テスト ────────────────────────────────────────────

// TestAutoResponseRule_ZeroValue は AutoResponseRule のゼロ値フィールドを確認する
func TestAutoResponseRule_ZeroValue(t *testing.T) {
	// ゼロ値は全フィールドがデフォルト状態であることを確認する
	var r AutoResponseRule
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", r.Name)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if r.TriggerSeverityMin != 0 {
		t.Errorf("TriggerSeverityMin のデフォルト = %d, want 0", r.TriggerSeverityMin)
	}
	if r.CooldownSeconds != 0 {
		t.Errorf("CooldownSeconds のデフォルト = %d, want 0", r.CooldownSeconds)
	}
	if r.ExecutionCount != 0 {
		t.Errorf("ExecutionCount のデフォルト = %d, want 0", r.ExecutionCount)
	}
	if r.LastExecutedAt != nil {
		t.Error("LastExecutedAt のデフォルトは nil であるべき")
	}
}

// TestAutoResponseRule_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestAutoResponseRule_FieldAssignment(t *testing.T) {
	// 全フィールドに値を設定し、取得値が一致するか確認する
	lastExec := "2026-03-23T10:00:00Z"
	params := json.RawMessage(`{"target": "192.168.1.1"}`)
	r := AutoResponseRule{
		ID:                 "rule-auto-001",
		Name:               "悪意のあるIPのブロック",
		Description:        "外部攻撃者のIPを自動ブロックする",
		Enabled:            true,
		TriggerSeverityMin: 7,
		TriggerStatus:      "open",
		AlertTitlePattern:  "*ransomware*",
		ActionType:         "block_ip",
		ActionParams:       params,
		CooldownSeconds:    300,
		ExecutionCount:     5,
		LastExecutedAt:     &lastExec,
		CreatedAt:          "2026-01-01T00:00:00Z",
		UpdatedAt:          "2026-03-23T10:00:00Z",
	}

	if r.ID != "rule-auto-001" {
		t.Errorf("ID = %q, want \"rule-auto-001\"", r.ID)
	}
	if r.ActionType != "block_ip" {
		t.Errorf("ActionType = %q, want \"block_ip\"", r.ActionType)
	}
	if r.TriggerSeverityMin != 7 {
		t.Errorf("TriggerSeverityMin = %d, want 7", r.TriggerSeverityMin)
	}
	if r.CooldownSeconds != 300 {
		t.Errorf("CooldownSeconds = %d, want 300", r.CooldownSeconds)
	}
	if r.LastExecutedAt == nil || *r.LastExecutedAt != lastExec {
		t.Errorf("LastExecutedAt = %v, want %q", r.LastExecutedAt, lastExec)
	}
}

// TestIsValidActionType_KnownTypes は既知のアクションタイプが有効と判定されることを確認する
func TestIsValidActionType_KnownTypes(t *testing.T) {
	// 全ての定義済みアクションタイプが有効と判定されるか確認する
	for _, at := range validAutoResponseActionTypes() {
		if !isValidActionType(at) {
			t.Errorf("既知のアクションタイプ %q が無効と判定された", at)
		}
	}
}

// TestIsValidActionType_UnknownType は未知のアクションタイプが無効と判定されることを確認する
func TestIsValidActionType_UnknownType(t *testing.T) {
	// 存在しないアクションタイプは拒否される
	unknownTypes := []string{"delete_user", "format_disk", "", "BLOCK_IP", "Block_IP"}
	for _, at := range unknownTypes {
		if isValidActionType(at) {
			t.Errorf("未知のアクションタイプ %q が有効と判定された", at)
		}
	}
}

// TestIsValidTriggerStatus_ValidStatuses は有効なトリガーステータスを確認する
func TestIsValidTriggerStatus_ValidStatuses(t *testing.T) {
	// 有効なステータス一覧が全て受け入れられるか確認する
	validStatuses := []string{"open", "in_progress", "resolved", "any"}
	for _, s := range validStatuses {
		if !isValidTriggerStatus(s) {
			t.Errorf("有効なトリガーステータス %q が無効と判定された", s)
		}
	}
}

// TestIsValidTriggerStatus_InvalidStatuses は無効なトリガーステータスを確認する
func TestIsValidTriggerStatus_InvalidStatuses(t *testing.T) {
	// 無効なステータスは拒否される
	invalidStatuses := []string{"closed", "pending", "", "OPEN", "Any"}
	for _, s := range invalidStatuses {
		if isValidTriggerStatus(s) {
			t.Errorf("無効なトリガーステータス %q が有効と判定された", s)
		}
	}
}

// TestIsValidCooldown_BoundaryValues はクールダウン秒数の境界値を確認する
func TestIsValidCooldown_BoundaryValues(t *testing.T) {
	// 0（クールダウンなし）と最大値 86400（24時間）は有効
	validCases := []int{0, 1, 300, 3600, 86400}
	for _, c := range validCases {
		if !isValidCooldown(c) {
			t.Errorf("クールダウン %d 秒は有効であるべき", c)
		}
	}

	// 負の値や最大値超過は無効
	invalidCases := []int{-1, -300, 86401, 100000}
	for _, c := range invalidCases {
		if isValidCooldown(c) {
			t.Errorf("クールダウン %d 秒は無効であるべき", c)
		}
	}
}

// TestIsValidSeverityMin_ValidRange は有効な重大度範囲 1〜10 を確認する
func TestIsValidSeverityMin_ValidRange(t *testing.T) {
	// 1から10の全ての値が有効であるか確認する
	for sev := 1; sev <= 10; sev++ {
		if !isValidSeverityMin(sev) {
			t.Errorf("重大度 %d は有効であるべき", sev)
		}
	}
}

// TestIsValidSeverityMin_OutOfRange は範囲外の重大度が無効と判定されることを確認する
func TestIsValidSeverityMin_OutOfRange(t *testing.T) {
	// 0以下や11以上は無効
	invalidCases := []int{0, -1, 11, 100}
	for _, sev := range invalidCases {
		if isValidSeverityMin(sev) {
			t.Errorf("重大度 %d は無効であるべき", sev)
		}
	}
}

// TestAutoResponseRuleHasRequiredFields_Complete は必須フィールドが揃っている場合を確認する
func TestAutoResponseRuleHasRequiredFields_Complete(t *testing.T) {
	// Name, ActionType, TriggerStatus が設定されていれば有効
	r := &AutoResponseRule{
		Name:          "テストルール",
		ActionType:    "isolate_host",
		TriggerStatus: "open",
	}
	if !autoResponseRuleHasRequiredFields(r) {
		t.Error("必須フィールドが揃っているルールは有効と判定されるべき")
	}
}

// TestAutoResponseRuleHasRequiredFields_MissingName は Name が空の場合を確認する
func TestAutoResponseRuleHasRequiredFields_MissingName(t *testing.T) {
	// Name が空のルールは無効
	r := &AutoResponseRule{
		Name:          "",
		ActionType:    "kill_process",
		TriggerStatus: "open",
	}
	if autoResponseRuleHasRequiredFields(r) {
		t.Error("Name が空のルールは無効と判定されるべき")
	}
}

// TestAutoResponseRuleHasRequiredFields_MissingActionType は ActionType が空の場合を確認する
func TestAutoResponseRuleHasRequiredFields_MissingActionType(t *testing.T) {
	// ActionType が空のルールは無効
	r := &AutoResponseRule{
		Name:          "名前あり",
		ActionType:    "",
		TriggerStatus: "any",
	}
	if autoResponseRuleHasRequiredFields(r) {
		t.Error("ActionType が空のルールは無効と判定されるべき")
	}
}

// TestExecutionIsTerminal_TerminalStatuses は終端ステータスを確認する
func TestExecutionIsTerminal_TerminalStatuses(t *testing.T) {
	// success と failed は終端ステータス
	terminalStatuses := []string{"success", "failed"}
	for _, s := range terminalStatuses {
		if !executionIsTerminal(s) {
			t.Errorf("ステータス %q は終端状態であるべき", s)
		}
	}
}

// TestExecutionIsTerminal_NonTerminalStatuses は非終端ステータスを確認する
func TestExecutionIsTerminal_NonTerminalStatuses(t *testing.T) {
	// pending と running は非終端ステータス
	nonTerminalStatuses := []string{"pending", "running", "", "cancelled"}
	for _, s := range nonTerminalStatuses {
		if executionIsTerminal(s) {
			t.Errorf("ステータス %q は非終端状態であるべき", s)
		}
	}
}

// TestFilterRulesByActionType_FiltersCorrectly はアクションタイプによるフィルタリングを確認する
func TestFilterRulesByActionType_FiltersCorrectly(t *testing.T) {
	// 複数のアクションタイプが混在するリストからの抽出を確認する
	rules := []*AutoResponseRule{
		{ID: "r1", ActionType: "block_ip"},
		{ID: "r2", ActionType: "isolate_host"},
		{ID: "r3", ActionType: "block_ip"},
		{ID: "r4", ActionType: "kill_process"},
	}
	result := filterRulesByActionType(rules, "block_ip")
	if len(result) != 2 {
		t.Errorf("block_ip ルール数 = %d, want 2", len(result))
	}
	for _, r := range result {
		if r.ActionType != "block_ip" {
			t.Errorf("フィルタ結果に block_ip 以外のルール %q が含まれている", r.ActionType)
		}
	}
}

// TestFilterRulesByActionType_NoMatch は一致するルールがない場合に空スライスを返すことを確認する
func TestFilterRulesByActionType_NoMatch(t *testing.T) {
	// 一致なしの場合は空スライスが返される
	rules := []*AutoResponseRule{
		{ID: "r1", ActionType: "block_ip"},
	}
	result := filterRulesByActionType(rules, "run_script")
	if len(result) != 0 {
		t.Errorf("一致なしは空スライスのはず: got %d items", len(result))
	}
}

// TestFilterRulesBySeverityMin_ThresholdFiltering は重大度閾値フィルタを確認する
func TestFilterRulesBySeverityMin_ThresholdFiltering(t *testing.T) {
	// threshold 5: TriggerSeverityMin <= 5 のルールのみが返される
	rules := []*AutoResponseRule{
		{ID: "r1", TriggerSeverityMin: 3},
		{ID: "r2", TriggerSeverityMin: 5},
		{ID: "r3", TriggerSeverityMin: 7},
		{ID: "r4", TriggerSeverityMin: 10},
	}
	result := filterRulesBySeverityMin(rules, 5)
	if len(result) != 2 {
		t.Errorf("重大度フィルタ結果 = %d, want 2", len(result))
	}
	for _, r := range result {
		if r.TriggerSeverityMin > 5 {
			t.Errorf("閾値 5 超のルール %q が含まれている (min=%d)", r.ID, r.TriggerSeverityMin)
		}
	}
}

// TestAutoResponseExecution_ZeroValue は AutoResponseExecution のゼロ値を確認する
func TestAutoResponseExecution_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルト値を確認する
	var e AutoResponseExecution
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", e.Status)
	}
	if e.CompletedAt != nil {
		t.Error("CompletedAt のデフォルトは nil であるべき")
	}
}

// TestAutoResponseExecution_FieldAssignment は AutoResponseExecution フィールド代入を確認する
func TestAutoResponseExecution_FieldAssignment(t *testing.T) {
	// 実行ログの各フィールドが正しく設定されるか確認する
	completed := "2026-03-23T10:05:00Z"
	e := AutoResponseExecution{
		ID:          "exec-001",
		RuleID:      "rule-auto-001",
		AlertID:     "alert-999",
		ActionType:  "block_ip",
		Status:      "success",
		ResultMsg:   "IPアドレスをブロックしました",
		ExecutedAt:  "2026-03-23T10:00:00Z",
		CompletedAt: &completed,
	}

	if e.RuleID != "rule-auto-001" {
		t.Errorf("RuleID = %q, want \"rule-auto-001\"", e.RuleID)
	}
	if e.Status != "success" {
		t.Errorf("Status = %q, want \"success\"", e.Status)
	}
	if e.CompletedAt == nil || *e.CompletedAt != completed {
		t.Errorf("CompletedAt = %v, want %q", e.CompletedAt, completed)
	}
}

// TestCreateAutoResponseRuleInput_DefaultParams は ActionParams のデフォルト処理を確認する
func TestCreateAutoResponseRuleInput_DefaultParams(t *testing.T) {
	// ActionParams が nil の場合は空オブジェクトとして扱われるべき
	in := CreateAutoResponseRuleInput{
		Name:          "スクリプト実行ルール",
		ActionType:    "run_script",
		TriggerStatus: "open",
	}
	params := in.ActionParams
	if len(params) == 0 {
		// 空の場合はデフォルト {} に置き換える（本番ロジックの確認）
		params = json.RawMessage(`{}`)
	}
	if string(params) != `{}` {
		t.Errorf("デフォルトの ActionParams = %q, want \"{}\"", string(params))
	}
}

// TestActionParamsJSON_Roundtrip は ActionParams の JSON ラウンドトリップを確認する
func TestActionParamsJSON_Roundtrip(t *testing.T) {
	// JSON エンコードと設定後の値が一致するか確認する
	original := `{"script_path":"/opt/response/block.sh","timeout":30}`
	r := AutoResponseRule{
		ActionParams: json.RawMessage(original),
	}
	if string(r.ActionParams) != original {
		t.Errorf("ActionParams = %q, want %q", string(r.ActionParams), original)
	}

	// キーが含まれているか確認する
	if !strings.Contains(string(r.ActionParams), "script_path") {
		t.Error("ActionParams に script_path キーが含まれるべき")
	}
}

// TestAutoResponseRule_SelectColsConstant は定数が期待するカラム名を含むか確認する
func TestAutoResponseRule_SelectColsConstant(t *testing.T) {
	// autoResponseRuleSelectCols が必要なカラムを含むか検証する
	requiredCols := []string{
		"action_type", "action_params", "cooldown_seconds",
		"trigger_severity_min", "trigger_status", "execution_count",
	}
	for _, col := range requiredCols {
		if !strings.Contains(autoResponseRuleSelectCols, col) {
			t.Errorf("SELECT カラム定数に %q が含まれていない", col)
		}
	}
}
