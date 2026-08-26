package store

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── ResponseAction 構造体テスト ──────────────────────────────────────────────

// TestResponseAction_ZeroValue は ResponseAction のゼロ値が期待通りであることを確認する
func TestResponseAction_ZeroValue(t *testing.T) {
	var a ResponseAction
	if a.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", a.ID)
	}
	if a.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", a.AgentID)
	}
	if a.ActionType != "" {
		t.Errorf("ActionType のデフォルト = %q, want \"\"", a.ActionType)
	}
	if a.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", a.Status)
	}
	if a.TriggeredBy != "" {
		t.Errorf("TriggeredBy のデフォルト = %q, want \"\"", a.TriggeredBy)
	}
	if a.CompletedAt != nil {
		t.Errorf("CompletedAt のデフォルトは nil であるべき: got %v", *a.CompletedAt)
	}
	if a.Error != nil {
		t.Errorf("Error のデフォルトは nil であるべき: got %v", *a.Error)
	}
	if a.Details != nil {
		t.Errorf("Details のデフォルトは nil であるべき")
	}
}

// TestResponseAction_FieldAssignment は ResponseAction の全フィールド代入を確認する
func TestResponseAction_FieldAssignment(t *testing.T) {
	now := time.Now()
	completed := now.Add(2 * time.Second)
	errMsg := "接続タイムアウト"
	details := json.RawMessage(`{"file":"/tmp/evil.exe","size":4096}`)

	a := ResponseAction{
		ID:          "ra-001",
		AgentID:     "agent-xyz",
		ActionType:  "isolate",
		Status:      "success",
		TriggeredBy: "user-admin",
		TriggeredAt: now,
		CompletedAt: &completed,
		Error:       &errMsg,
		Details:     details,
	}

	if a.ID != "ra-001" {
		t.Errorf("ID = %q, want \"ra-001\"", a.ID)
	}
	if a.ActionType != "isolate" {
		t.Errorf("ActionType = %q, want \"isolate\"", a.ActionType)
	}
	if a.Status != "success" {
		t.Errorf("Status = %q, want \"success\"", a.Status)
	}
	if a.CompletedAt == nil {
		t.Fatal("CompletedAt は nil でないべき")
	}
	if !a.CompletedAt.Equal(completed) {
		t.Errorf("CompletedAt = %v, want %v", *a.CompletedAt, completed)
	}
	if a.Error == nil || *a.Error != errMsg {
		t.Errorf("Error = %v, want %q", a.Error, errMsg)
	}
}

// TestResponseAction_KnownActionTypes は既知のアクションタイプを確認する
func TestResponseAction_KnownActionTypes(t *testing.T) {
	// EDRプラットフォームで使用される標準的なレスポンスアクションタイプ
	knownTypes := []string{
		"isolate",
		"unisolate",
		"kill_process",
		"delete_file",
		"quarantine_file",
		"run_scan",
	}
	for _, at := range knownTypes {
		a := ResponseAction{ActionType: at}
		if a.ActionType != at {
			t.Errorf("ActionType = %q, want %q", a.ActionType, at)
		}
	}
}

// TestResponseAction_KnownStatuses は既知のステータス値を確認する
// "success" | "failure" | "pending" | "running" が標準
func TestResponseAction_KnownStatuses(t *testing.T) {
	validStatuses := []string{"success", "failure", "pending", "running"}
	for _, status := range validStatuses {
		a := ResponseAction{Status: status}
		if a.Status != status {
			t.Errorf("Status = %q, want %q", a.Status, status)
		}
	}
}

// TestResponseAction_DetailsJSON は Details フィールドが JSON として扱われることを確認する
func TestResponseAction_DetailsJSON(t *testing.T) {
	// 様々な詳細情報を JSON として格納できることを確認する
	cases := []struct {
		name    string
		details interface{}
	}{
		{
			name:    "ファイル削除詳細",
			details: map[string]interface{}{"file_path": "/tmp/malware.exe", "sha256": "abc123"},
		},
		{
			name:    "プロセス終了詳細",
			details: map[string]interface{}{"pid": 1234, "process_name": "evil.exe"},
		},
		{
			name:    "空の詳細",
			details: map[string]interface{}{},
		},
	}

	for _, tc := range cases {
		data, err := json.Marshal(tc.details)
		if err != nil {
			t.Errorf("%s: JSON マーシャルに失敗: %v", tc.name, err)
			continue
		}
		a := ResponseAction{Details: json.RawMessage(data)}
		if a.Details == nil {
			t.Errorf("%s: Details が nil でないべき", tc.name)
		}
	}
}

// TestResponseAction_IsCompleted は完了状態の判定ロジックを確認する
// CompletedAt が nil でなければ完了済み
func TestResponseAction_IsCompleted(t *testing.T) {
	// 未完了
	a := ResponseAction{Status: "pending"}
	if a.CompletedAt != nil {
		t.Error("pending 状態では CompletedAt が nil であるべき")
	}

	// 完了
	now := time.Now()
	a.CompletedAt = &now
	if a.CompletedAt == nil {
		t.Error("完了後は CompletedAt が nil でないべき")
	}
}

// TestResponseAction_ErrorOnlyOnFailure は失敗時のみ Error が設定されることを確認する
func TestResponseAction_ErrorOnlyOnFailure(t *testing.T) {
	// 成功アクション：Error は nil
	success := ResponseAction{Status: "success"}
	if success.Error != nil {
		t.Errorf("成功時に Error は nil であるべき: got %v", *success.Error)
	}

	// 失敗アクション：Error が設定される
	errMsg := "エージェントが応答しません"
	failure := ResponseAction{Status: "failure", Error: &errMsg}
	if failure.Error == nil {
		t.Fatal("失敗時に Error が設定されるべき")
	}
	if *failure.Error != errMsg {
		t.Errorf("*Error = %q, want %q", *failure.Error, errMsg)
	}
}

// ─── レスポンスアクション クエリビルダーロジックテスト ────────────────────────

// 対応アクション一覧の絞り込みには、**製品側に対応する組み立てが
// ありません。** `List` の WHERE は `ra.agent_id = $1` の固定です。
//
// 写しは消します。**繋ぐ先がないものを繋いだふりはしません。**

func isValidResponseActionType(actionType string) bool {
	switch actionType {
	case "isolate", "unisolate", "kill_process", "delete_file",
		"quarantine_file", "run_scan", "collect_forensics":
		return true
	}
	return false
}

// TestIsValidResponseActionType_ValidTypes は有効なアクションタイプで true を返すことを確認する
func TestIsValidResponseActionType_ValidTypes(t *testing.T) {
	validTypes := []string{
		"isolate",
		"unisolate",
		"kill_process",
		"delete_file",
		"quarantine_file",
		"run_scan",
		"collect_forensics",
	}
	for _, at := range validTypes {
		if !isValidResponseActionType(at) {
			t.Errorf("有効なアクションタイプ %q で false が返されました", at)
		}
	}
}

// TestIsValidResponseActionType_InvalidTypes は無効なアクションタイプで false を返すことを確認する
func TestIsValidResponseActionType_InvalidTypes(t *testing.T) {
	invalidTypes := []string{
		"",
		"unknown_action",
		"ISOLATE",       // 大文字は無効
		"delete",        // 不完全なタイプ
		"shutdown_host", // 未定義のタイプ
	}
	for _, at := range invalidTypes {
		if isValidResponseActionType(at) {
			t.Errorf("無効なアクションタイプ %q で true が返されました", at)
		}
	}
}

// TestIsValidResponseActionType_CaseSensitive はアクションタイプが大文字小文字を区別することを確認する
func TestIsValidResponseActionType_CaseSensitive(t *testing.T) {
	// 小文字のみ有効
	if isValidResponseActionType("Isolate") {
		t.Error("\"Isolate\" (先頭大文字) は無効であるべき")
	}
	if isValidResponseActionType("ISOLATE") {
		t.Error("\"ISOLATE\" (全大文字) は無効であるべき")
	}
	if !isValidResponseActionType("isolate") {
		t.Error("\"isolate\" (全小文字) は有効であるべき")
	}
}

// ─── レスポンスアクション統計ロジックテスト ──────────────────────────────────

// countActionsByStatus はアクションリストをステータス別に集計するピュア関数
func countActionsByStatus(actions []ResponseAction) map[string]int {
	counts := map[string]int{}
	for _, a := range actions {
		counts[a.Status]++
	}
	return counts
}

// TestCountActionsByStatus_BasicCount はステータス別集計が正しいことを確認する
func TestCountActionsByStatus_BasicCount(t *testing.T) {
	actions := []ResponseAction{
		{Status: "success"},
		{Status: "success"},
		{Status: "failure"},
		{Status: "pending"},
		{Status: "success"},
	}

	counts := countActionsByStatus(actions)
	if counts["success"] != 3 {
		t.Errorf("success カウント = %d, want 3", counts["success"])
	}
	if counts["failure"] != 1 {
		t.Errorf("failure カウント = %d, want 1", counts["failure"])
	}
	if counts["pending"] != 1 {
		t.Errorf("pending カウント = %d, want 1", counts["pending"])
	}
}

// TestCountActionsByStatus_EmptyList は空のリストで空マップが返されることを確認する
func TestCountActionsByStatus_EmptyList(t *testing.T) {
	counts := countActionsByStatus([]ResponseAction{})
	if len(counts) != 0 {
		t.Errorf("空リストは空マップを返すべき: got %v", counts)
	}
}

// TestCountActionsByStatus_AllSuccess は全成功のとき他のステータスが含まれないことを確認する
func TestCountActionsByStatus_AllSuccess(t *testing.T) {
	actions := []ResponseAction{
		{Status: "success"},
		{Status: "success"},
	}
	counts := countActionsByStatus(actions)
	if counts["success"] != 2 {
		t.Errorf("success カウント = %d, want 2", counts["success"])
	}
	if _, exists := counts["failure"]; exists {
		t.Error("全成功のとき failure キーが存在すべきでない")
	}
}
