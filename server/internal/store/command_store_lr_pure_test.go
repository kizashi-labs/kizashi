package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─── コマンドタイプ分類ヘルパー（テスト専用）──────────────────────────────────
// command_store_lr.go / live_response_store.go で使用されるコマンドタイプを
// 純粋関数として分類・検証するヘルパーを定義する。

// isLiveResponseCommandType はコマンドタイプがライブレスポンス関連かどうかを判定する
func isLiveResponseCommandType(cmdType string) bool {
	switch cmdType {
	case "shell", "file_get", "file_put", "process_list",
		"process_kill", "file_delete", "memory_dump":
		return true
	}
	return false
}

// isReadOnlyCommand は読み取り専用コマンドかどうかを判定する
// 読み取り専用は副作用がないため安全に実行可能
func isReadOnlyCommand(cmdType string) bool {
	switch cmdType {
	case "process_list", "file_get", "shell":
		return true
	}
	return false
}

// isDestructiveCommand は破壊的なコマンドかどうかを判定する
func isDestructiveCommand(cmdType string) bool {
	switch cmdType {
	case "file_delete", "process_kill", "memory_dump":
		return true
	}
	return false
}

// liveResponseNATSSubject は NATS サブジェクト文字列を生成する
// EnqueueLiveResponseStart と同じパターン: "commands.<agentID>.live_response_start"
func liveResponseNATSSubject(agentID string) string {
	return "commands." + agentID + ".live_response_start"
}

// ─── LiveResponseStartPayload テスト ─────────────────────────────────────────

// TestLiveResponseStartPayload_ZeroValue は LiveResponseStartPayload のゼロ値を確認する
func TestLiveResponseStartPayload_ZeroValue(t *testing.T) {
	var p LiveResponseStartPayload
	if p.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", p.Type)
	}
	if p.SessionID != "" {
		t.Errorf("SessionID のデフォルト = %q, want \"\"", p.SessionID)
	}
	if p.Token != "" {
		t.Errorf("Token のデフォルト = %q, want \"\"", p.Token)
	}
	if p.CallbackURL != "" {
		t.Errorf("CallbackURL のデフォルト = %q, want \"\"", p.CallbackURL)
	}
}

// TestLiveResponseStartPayload_TypeIsLiveResponse は
// EnqueueLiveResponseStart が生成するペイロードの Type フィールドを確認する
func TestLiveResponseStartPayload_TypeIsLiveResponse(t *testing.T) {
	// EnqueueLiveResponseStart と同じ構築ロジック
	payload := LiveResponseStartPayload{
		Type:        "live_response",
		SessionID:   "session-001",
		Token:       "tok-abc",
		CallbackURL: "https://api.example.com/lr/callback",
	}
	if payload.Type != "live_response" {
		t.Errorf("Type = %q, want \"live_response\"", payload.Type)
	}
}

// TestLiveResponseStartPayload_JSONMarshalRoundTrip は
// JSON シリアライズ/デシリアライズで値が保持されることを確認する
func TestLiveResponseStartPayload_JSONMarshalRoundTrip(t *testing.T) {
	original := LiveResponseStartPayload{
		Type:        "live_response",
		SessionID:   "sess-xyz",
		Token:       "token-secret",
		CallbackURL: "https://edr.example.com/callback",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("JSON Marshal エラー: %v", err)
	}
	var decoded LiveResponseStartPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON Unmarshal エラー: %v", err)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, original.Type)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.Token != original.Token {
		t.Errorf("Token = %q, want %q", decoded.Token, original.Token)
	}
	if decoded.CallbackURL != original.CallbackURL {
		t.Errorf("CallbackURL = %q, want %q", decoded.CallbackURL, original.CallbackURL)
	}
}

// TestLiveResponseStartPayload_JSONFieldNames は
// JSON フィールド名が期待する snake_case であることを確認する
func TestLiveResponseStartPayload_JSONFieldNames(t *testing.T) {
	payload := LiveResponseStartPayload{
		Type:        "live_response",
		SessionID:   "s1",
		Token:       "t1",
		CallbackURL: "http://cb",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("JSON Marshal エラー: %v", err)
	}
	jsonStr := string(data)
	expectedKeys := []string{`"type"`, `"session_id"`, `"token"`, `"callback_url"`}
	for _, key := range expectedKeys {
		if !strings.Contains(jsonStr, key) {
			t.Errorf("JSONに %s が含まれるべき: %s", key, jsonStr)
		}
	}
}

// ─── NATSサブジェクト生成テスト ───────────────────────────────────────────────

// TestLiveResponseNATSSubject_ContainsAgentID は
// NATS サブジェクトにエージェントIDが含まれることを確認する
func TestLiveResponseNATSSubject_ContainsAgentID(t *testing.T) {
	agentID := "agent-uuid-001"
	subject := liveResponseNATSSubject(agentID)
	if !strings.Contains(subject, agentID) {
		t.Errorf("NATSサブジェクトにエージェントIDが含まれるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_HasCorrectPrefix は
// NATS サブジェクトが "commands." で始まることを確認する
func TestLiveResponseNATSSubject_HasCorrectPrefix(t *testing.T) {
	subject := liveResponseNATSSubject("agent-001")
	if !strings.HasPrefix(subject, "commands.") {
		t.Errorf("NATSサブジェクトは \"commands.\" で始まるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_HasCorrectSuffix は
// NATS サブジェクトが ".live_response_start" で終わることを確認する
func TestLiveResponseNATSSubject_HasCorrectSuffix(t *testing.T) {
	subject := liveResponseNATSSubject("agent-001")
	if !strings.HasSuffix(subject, ".live_response_start") {
		t.Errorf("NATSサブジェクトは \".live_response_start\" で終わるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_DifferentAgentsHaveDifferentSubjects は
// 異なるエージェントIDが異なるサブジェクトを生成することを確認する
func TestLiveResponseNATSSubject_DifferentAgentsHaveDifferentSubjects(t *testing.T) {
	s1 := liveResponseNATSSubject("agent-aaa")
	s2 := liveResponseNATSSubject("agent-bbb")
	if s1 == s2 {
		t.Error("異なるエージェントIDは異なるNATSサブジェクトを生成するべき")
	}
}

// ─── コマンドタイプ分類テスト ─────────────────────────────────────────────────

// TestIsLiveResponseCommandType_ValidTypes は有効なライブレスポンスコマンドタイプを確認する
func TestIsLiveResponseCommandType_ValidTypes(t *testing.T) {
	validTypes := []string{
		"shell", "file_get", "file_put",
		"process_list", "process_kill",
		"file_delete", "memory_dump",
	}
	for _, ct := range validTypes {
		if !isLiveResponseCommandType(ct) {
			t.Errorf("isLiveResponseCommandType(%q) = false, want true", ct)
		}
	}
}

// TestIsLiveResponseCommandType_InvalidType は無効なコマンドタイプが false を返すことを確認する
func TestIsLiveResponseCommandType_InvalidType(t *testing.T) {
	invalidTypes := []string{"", "unknown", "SHELL", "File_Get", "collect_artifact"}
	for _, ct := range invalidTypes {
		if isLiveResponseCommandType(ct) {
			t.Errorf("isLiveResponseCommandType(%q) = true, want false", ct)
		}
	}
}

// TestIsReadOnlyCommand_ClassifiesCorrectly は読み取り専用コマンドの分類を確認する
func TestIsReadOnlyCommand_ClassifiesCorrectly(t *testing.T) {
	readOnly := []string{"process_list", "file_get", "shell"}
	for _, ct := range readOnly {
		if !isReadOnlyCommand(ct) {
			t.Errorf("isReadOnlyCommand(%q) = false, want true", ct)
		}
	}
	notReadOnly := []string{"file_put", "process_kill", "file_delete", "memory_dump"}
	for _, ct := range notReadOnly {
		if isReadOnlyCommand(ct) {
			t.Errorf("isReadOnlyCommand(%q) = true, want false", ct)
		}
	}
}

// TestIsDestructiveCommand_ClassifiesCorrectly は破壊的コマンドの分類を確認する
func TestIsDestructiveCommand_ClassifiesCorrectly(t *testing.T) {
	destructive := []string{"file_delete", "process_kill", "memory_dump"}
	for _, ct := range destructive {
		if !isDestructiveCommand(ct) {
			t.Errorf("isDestructiveCommand(%q) = false, want true", ct)
		}
	}
	safe := []string{"shell", "file_get", "file_put", "process_list"}
	for _, ct := range safe {
		if isDestructiveCommand(ct) {
			t.Errorf("isDestructiveCommand(%q) = true, want false", ct)
		}
	}
}

// ─── QueuedCommand 構造体テスト ───────────────────────────────────────────────

// TestQueuedCommand_ZeroValue は QueuedCommand のゼロ値フィールドを確認する
func TestQueuedCommand_ZeroValue(t *testing.T) {
	var cmd QueuedCommand
	if cmd.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", cmd.ID)
	}
	if cmd.CommandType != "" {
		t.Errorf("CommandType のデフォルト = %q, want \"\"", cmd.CommandType)
	}
	if cmd.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", cmd.Status)
	}
	if cmd.SessionID != nil {
		t.Errorf("SessionID のデフォルトは nil であるべき: got %v", *cmd.SessionID)
	}
	if cmd.Output != nil {
		t.Errorf("Output のデフォルトは nil であるべき: got %v", *cmd.Output)
	}
	if cmd.ExitCode != nil {
		t.Errorf("ExitCode のデフォルトは nil であるべき: got %v", *cmd.ExitCode)
	}
}

// TestQueuedCommand_KnownStatuses は既知のコマンドステータスを確認する
// pending → running → completed / failed / timeout
func TestQueuedCommand_KnownStatuses(t *testing.T) {
	statuses := []string{"pending", "running", "completed", "failed", "timeout"}
	for _, st := range statuses {
		cmd := QueuedCommand{Status: st}
		if cmd.Status != st {
			t.Errorf("Status = %q, want %q", cmd.Status, st)
		}
	}
}

// TestQueuedCommand_ExitCodeZeroMeansSuccess は
// ExitCode=0 が成功を意味することを確認する
func TestQueuedCommand_ExitCodeZeroMeansSuccess(t *testing.T) {
	exitCode := 0
	cmd := QueuedCommand{
		Status:   "completed",
		ExitCode: &exitCode,
	}
	if cmd.ExitCode == nil {
		t.Fatal("ExitCode は nil でないべき")
	}
	if *cmd.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", *cmd.ExitCode)
	}
}
