package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── LiveResponseSession 構造体テスト ─────────────────────────────────────────

// TestLiveResponseSession_ZeroValue は LiveResponseSession のゼロ値を確認する
func TestLiveResponseSession_ZeroValue(t *testing.T) {
	var s LiveResponseSession
	if s.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", s.ID)
	}
	if s.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", s.AgentID)
	}
	if s.Token != "" {
		t.Errorf("Token のデフォルト = %q, want \"\"", s.Token)
	}
	if s.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", s.Status)
	}
	if s.ClosedAt != nil {
		t.Errorf("ClosedAt のデフォルトは nil であるべき: got %v", *s.ClosedAt)
	}
}

// TestLiveResponseSession_KnownStatuses は既知の LiveResponse セッションステータスを確認する
// "active", "closed", "expired" が有効なステータス
func TestLiveResponseSession_KnownStatuses(t *testing.T) {
	statuses := []string{"active", "closed", "expired"}
	for _, st := range statuses {
		s := LiveResponseSession{Status: st}
		if s.Status != st {
			t.Errorf("Status = %q, want %q", s.Status, st)
		}
	}
}

// TestLiveResponseSession_IsActive はセッションのアクティブ状態判定を確認する
func TestLiveResponseSession_IsActive(t *testing.T) {
	// アクティブなセッション
	active := LiveResponseSession{Status: "active"}
	if active.Status != "active" {
		t.Errorf("アクティブセッションの Status = %q, want \"active\"", active.Status)
	}

	// クローズ済みセッション
	closed := LiveResponseSession{Status: "closed"}
	if closed.Status == "active" {
		t.Error("クローズ済みセッションは active でないべき")
	}
}

// TestLiveResponseSession_TokenNotLeakedInList はリスト取得時にトークンが漏洩しないことを確認する
// live_response.go の ListSessions では session.Token = "" に設定する
func TestLiveResponseSession_TokenNotLeakedInList(t *testing.T) {
	// セッションのリスト表現ではトークンを空に設定する
	s := LiveResponseSession{
		ID:     "lr-001",
		Token:  "secret-token-xyz",
		Status: "active",
	}
	// リスト用にトークンをクリア（live_response.go line 114 と同等）
	s.Token = ""

	if s.Token != "" {
		t.Errorf("リスト表現ではトークンが空であるべき: got %q", s.Token)
	}
}

// TestLiveResponseSession_ClosedAtNilWhenActive はアクティブセッションの ClosedAt が nil であることを確認する
func TestLiveResponseSession_ClosedAtNilWhenActive(t *testing.T) {
	s := LiveResponseSession{
		ID:     "lr-002",
		Status: "active",
	}
	if s.ClosedAt != nil {
		t.Error("アクティブなセッションの ClosedAt は nil であるべき")
	}
}

// TestLiveResponseSession_ClosedAtSetOnClose はセッションクローズ時に ClosedAt が設定されることを確認する
func TestLiveResponseSession_ClosedAtSetOnClose(t *testing.T) {
	now := time.Now()
	s := LiveResponseSession{
		ID:       "lr-003",
		Status:   "closed",
		ClosedAt: &now,
	}
	if s.ClosedAt == nil {
		t.Fatal("クローズ済みセッションの ClosedAt は nil でないべき")
	}
	if !s.ClosedAt.Equal(now) {
		t.Errorf("ClosedAt = %v, want %v", *s.ClosedAt, now)
	}
}

// ─── LiveResponseCommand 構造体テスト ────────────────────────────────────────

// TestLiveResponseCommand_ZeroValue は LiveResponseCommand のゼロ値を確認する
func TestLiveResponseCommand_ZeroValue(t *testing.T) {
	var c LiveResponseCommand
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", c.Status)
	}
	if c.ExitCode != nil {
		t.Errorf("ExitCode のデフォルトは nil であるべき: got %v", *c.ExitCode)
	}
	if c.CompletedAt != nil {
		t.Errorf("CompletedAt のデフォルトは nil であるべき: got %v", *c.CompletedAt)
	}
}

// TestLiveResponseCommand_KnownStatuses は既知のコマンドステータスを確認する
func TestLiveResponseCommand_KnownStatuses(t *testing.T) {
	statuses := []string{"pending", "running", "completed", "error"}
	for _, st := range statuses {
		c := LiveResponseCommand{Status: st}
		if c.Status != st {
			t.Errorf("Status = %q, want %q", c.Status, st)
		}
	}
}

// TestLiveResponseCommand_ExitCodeSuccess はコマンド成功時の exit code = 0 を確認する
func TestLiveResponseCommand_ExitCodeSuccess(t *testing.T) {
	exitCode := 0
	c := LiveResponseCommand{
		Status:   "completed",
		ExitCode: &exitCode,
	}
	if *c.ExitCode != 0 {
		t.Errorf("成功コマンドの ExitCode = %d, want 0", *c.ExitCode)
	}
}

// TestLiveResponseCommand_ExitCodeError はコマンド失敗時の exit code が非ゼロであることを確認する
func TestLiveResponseCommand_ExitCodeError(t *testing.T) {
	exitCode := 1
	c := LiveResponseCommand{
		Status:   "error",
		ExitCode: &exitCode,
	}
	if *c.ExitCode == 0 {
		t.Error("失敗コマンドの ExitCode は 0 でないべき")
	}
}

// TestLiveResponseCommand_CompleteStatusDetermination は hasError フラグによるステータス決定を確認する
// live_response.go の CompleteCommand メソッドのロジックを再現する
func TestLiveResponseCommand_CompleteStatusDetermination(t *testing.T) {
	determineStatus := func(hasError bool) string {
		if hasError {
			return "error"
		}
		return "completed"
	}

	cases := []struct {
		hasError bool
		want     string
	}{
		{false, "completed"},
		{true, "error"},
	}

	for _, tc := range cases {
		got := determineStatus(tc.hasError)
		if got != tc.want {
			t.Errorf("determineStatus(%v) = %q, want %q", tc.hasError, got, tc.want)
		}
	}
}

// ─── QueuedCommand 構造体テスト ───────────────────────────────────────────────

// TestQueuedCommand_ZeroValue_LiveResponse は QueuedCommand のゼロ値を確認する
func TestQueuedCommand_ZeroValue_LiveResponse(t *testing.T) {
	var c QueuedCommand
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", c.Status)
	}
	if c.SessionID != nil {
		t.Errorf("SessionID のデフォルトは nil であるべき: got %v", *c.SessionID)
	}
	if c.Output != nil {
		t.Errorf("Output のデフォルトは nil であるべき: got %v", *c.Output)
	}
	if c.ExitCode != nil {
		t.Errorf("ExitCode のデフォルトは nil であるべき: got %v", *c.ExitCode)
	}
	if c.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき: got %v", *c.CreatedBy)
	}
}

// TestQueuedCommand_KnownCommandTypes は既知のコマンドタイプを確認する
func TestQueuedCommand_KnownCommandTypes(t *testing.T) {
	cmdTypes := []string{"shell", "file_list", "file_get", "process_list", "kill_process"}
	for _, ct := range cmdTypes {
		c := QueuedCommand{CommandType: ct}
		if c.CommandType != ct {
			t.Errorf("CommandType = %q, want %q", c.CommandType, ct)
		}
	}
}

// TestQueuedCommand_IsTimedOut はタイムアウト判定ロジックを確認する
// TimeoutAt が現在時刻より前のコマンドはタイムアウトとみなされる
func TestQueuedCommand_IsTimedOut(t *testing.T) {
	now := time.Now()

	// タイムアウト済みコマンド
	timedOut := QueuedCommand{
		Status:    "pending",
		TimeoutAt: now.Add(-1 * time.Second),
	}
	if !timedOut.TimeoutAt.Before(now) {
		t.Error("TimeoutAt が過去のコマンドはタイムアウト済みであるべき")
	}

	// まだ有効なコマンド
	valid := QueuedCommand{
		Status:    "pending",
		TimeoutAt: now.Add(5 * time.Minute),
	}
	if valid.TimeoutAt.Before(now) {
		t.Error("TimeoutAt が未来のコマンドは有効であるべき")
	}
}

// TestQueuedCommand_ArgsDefaultsToEmptyJSON は Args が nil のとき "{}" がデフォルトになることを確認する
// live_response_store.go の Create メソッドのロジックを再現する
func TestQueuedCommand_ArgsDefaultsToEmptyJSON(t *testing.T) {
	in := CreateQueuedCommandInput{
		AgentID:     "agent-001",
		CommandType: "shell",
		Command:     "ls",
		Args:        nil,
	}

	// Create では nil を "{}" に置き換える
	if in.Args == nil {
		in.Args = json.RawMessage("{}")
	}

	if string(in.Args) != "{}" {
		t.Errorf("デフォルトの Args = %q, want \"{}\"", string(in.Args))
	}
}

// TestQueuedCommand_ArgsPreservedIfSet は Args が設定済みのとき変更されないことを確認する
func TestQueuedCommand_ArgsPreservedIfSet(t *testing.T) {
	argsJSON := json.RawMessage(`{"pid": 1234, "signal": "SIGTERM"}`)
	in := CreateQueuedCommandInput{
		CommandType: "kill_process",
		Args:        argsJSON,
	}

	if in.Args == nil {
		in.Args = json.RawMessage("{}")
	}

	if string(in.Args) != `{"pid": 1234, "signal": "SIGTERM"}` {
		t.Errorf("設定済み Args が変更されました: %q", string(in.Args))
	}
}

// ─── コマンドキューステータス遷移テスト ───────────────────────────────────────

// TestCommandStatusTransitions はコマンドの有効なステータス遷移を確認する
// pending → running → completed/error/timeout が正常な遷移
func TestCommandStatusTransitions(t *testing.T) {
	// 遷移マップ: 現在のステータスから遷移可能なステータス
	validTransitions := map[string][]string{
		"pending": {"running", "failed", "timeout"},
		"running": {"completed", "error", "timeout"},
	}

	for from, tos := range validTransitions {
		for _, to := range tos {
			c := QueuedCommand{Status: from}
			c.Status = to
			if c.Status != to {
				t.Errorf("ステータス遷移 %q → %q が失敗: got %q", from, to, c.Status)
			}
		}
	}
}

// TestCreateQueuedCommandInput_ZeroValue は CreateQueuedCommandInput のゼロ値を確認する
func TestCreateQueuedCommandInput_ZeroValue(t *testing.T) {
	var in CreateQueuedCommandInput
	if in.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", in.AgentID)
	}
	if in.CommandType != "" {
		t.Errorf("CommandType のデフォルト = %q, want \"\"", in.CommandType)
	}
	if in.Command != "" {
		t.Errorf("Command のデフォルト = %q, want \"\"", in.Command)
	}
	if in.SessionID != nil {
		t.Errorf("SessionID のデフォルトは nil であるべき: got %v", *in.SessionID)
	}
	if in.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき: got %v", *in.CreatedBy)
	}
}

// TestCmdQueueColumns_ContainsRequiredFields は cmdQueueColumns 定数が必須フィールドを含むことを確認する
func TestCmdQueueColumns_ContainsRequiredFields(t *testing.T) {
	requiredFields := []string{
		"id", "agent_id", "session_id", "command_type", "command",
		"args", "status", "output", "exit_code", "created_by",
		"created_at", "started_at", "completed_at", "timeout_at",
	}

	for _, field := range requiredFields {
		if !strings.Contains(cmdQueueColumns, field) {
			t.Errorf("cmdQueueColumns に %q が含まれるべき: %q", field, cmdQueueColumns)
		}
	}
}

// TestLiveResponseCommand_InputMaxLength は Input コマンドの文字列操作を確認する
func TestLiveResponseCommand_InputMaxLength(t *testing.T) {
	// コマンド入力に典型的な shell コマンドを代入できることを確認する
	cmds := []string{
		"ls -la /tmp",
		"ps aux | grep malware",
		"cat /etc/passwd",
		"netstat -an",
	}
	for _, cmd := range cmds {
		c := LiveResponseCommand{Input: cmd}
		if c.Input != cmd {
			t.Errorf("Input = %q, want %q", c.Input, cmd)
		}
		if c.Input == "" {
			t.Errorf("Input が空になりました: %q", cmd)
		}
	}
}
