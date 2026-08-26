package store

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// コマンド種別の分類（`isLiveResponseCommandType` /
// `isReadOnlyCommand` / `isDestructiveCommand`）は、**製品のどこにも
// ありません。** 検査の中だけで定義され、それ自身が試されていました。
//
// そのうえ中身が危うい。`shell` を「読み取り専用（副作用がないため安全に
// 実行可能）」に分類しています —— **`shell` は任意のコマンドを実行します。**
// この分類が権限判定に繋がっていたら、そのまま穴になります。繋がって
// いないので今は何も壊れていませんが、**「安全」と書かれた一覧が残って
// いるだけで、次に誰かが使います。**
//
// 消しました。分類が要るなら、それは製品側に足す話です
// （判断待ちの一覧にあります）。
//
// NATS のサブジェクト組み立ては本物 (`liveResponseSubject`) に向けました。

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
	subject := liveResponseSubject(agentID)
	if !strings.Contains(subject, agentID) {
		t.Errorf("NATSサブジェクトにエージェントIDが含まれるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_HasCorrectPrefix は
// NATS サブジェクトが "commands." で始まることを確認する
func TestLiveResponseNATSSubject_HasCorrectPrefix(t *testing.T) {
	subject := liveResponseSubject("agent-001")
	if !strings.HasPrefix(subject, "commands.") {
		t.Errorf("NATSサブジェクトは \"commands.\" で始まるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_HasCorrectSuffix は
// NATS サブジェクトが ".live_response_start" で終わることを確認する
func TestLiveResponseNATSSubject_HasCorrectSuffix(t *testing.T) {
	subject := liveResponseSubject("agent-001")
	if !strings.HasSuffix(subject, ".live_response_start") {
		t.Errorf("NATSサブジェクトは \".live_response_start\" で終わるべき: %q", subject)
	}
}

// TestLiveResponseNATSSubject_DifferentAgentsHaveDifferentSubjects は
// 異なるエージェントIDが異なるサブジェクトを生成することを確認する
func TestLiveResponseNATSSubject_DifferentAgentsHaveDifferentSubjects(t *testing.T) {
	s1 := liveResponseSubject("agent-aaa")
	s2 := liveResponseSubject("agent-bbb")
	if s1 == s2 {
		t.Error("異なるエージェントIDは異なるNATSサブジェクトを生成するべき")
	}
}

// ─── コマンドタイプ分類テスト ─────────────────────────────────────────────────

// TestIsLiveResponseCommandType_ValidTypes は有効なライブレスポンスコマンドタイプを確認する
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

// 送る側のサブジェクトが、受け取る側の購読パターンに一致すること。
//
// **文字列が2箇所にあります。** 片方だけ変えると購読が外れ、ライブ
// レスポンスの開始要求が届きません —— 画面からは「エージェントが応答
// しない」と同じ姿になります。
//
// 受け取る側は `cmd/ingestion` の `commands.*.live_response_start` です。
// あそこは package main なので呼べません。**パターンの側を読みます** ——
// 読めなければ落とします。読めないことを「一致した」と同じ結果には
// しません。
func TestTheSubjectMatchesWhatIngestionSubscribesTo(t *testing.T) {
	const path = "../../cmd/ingestion/main.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v。**購読側と照合できません**", path, err)
	}
	const quoted = `"commands.*.live_response_start"`
	if !strings.Contains(string(src), quoted) {
		t.Fatalf("%s に %s がありません。購読側が変わったのなら、"+
			"送る側 (liveResponseSubject) も見直してください", path, quoted)
	}

	pattern := strings.Trim(quoted, `"`)
	subject := liveResponseSubject("11111111-2222-3333-4444-555555555555")
	if !natsSubjectMatches(pattern, subject) {
		t.Errorf("送る側 %q が購読パターン %q に一致しません", subject, pattern)
	}
	// `*` は1トークンだけです。**この前提が崩れると、上の一致は
	// 何も言っていないことになります。**
	if natsSubjectMatches(pattern, "commands.a.b.live_response_start") {
		t.Error("`*` が複数トークンに一致しています")
	}
	if natsSubjectMatches(pattern, "commands.a.other") {
		t.Error("末尾が違うのに一致しています")
	}
}

// natsSubjectMatches implements NATS' single-token `*` wildcard.
func natsSubjectMatches(pattern, subject string) bool {
	p := strings.Split(pattern, ".")
	s := strings.Split(subject, ".")
	if len(p) != len(s) {
		return false
	}
	for i := range p {
		if p[i] != "*" && p[i] != s[i] {
			return false
		}
	}
	return true
}
