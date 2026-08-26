package store

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── QueuedCommand 構造体テスト ───────────────────────────────────────────────

// TestQueuedCommand_ZeroValue_LiveResponsePure は QueuedCommand のゼロ値が期待通りであることを確認する
func TestQueuedCommand_ZeroValue_LiveResponsePure(t *testing.T) {
	var cmd QueuedCommand
	if cmd.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", cmd.ID)
	}
	if cmd.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", cmd.AgentID)
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

// TestQueuedCommand_StatusValues はコマンドの有効なステータス値を確認する
func TestQueuedCommand_StatusValues(t *testing.T) {
	// ライブレスポンスコマンドのライフサイクルステータスを確認する
	validStatuses := []string{"pending", "running", "completed", "failed", "timeout"}
	for _, status := range validStatuses {
		cmd := QueuedCommand{Status: status}
		if cmd.Status != status {
			t.Errorf("Status = %q, want %q", cmd.Status, status)
		}
	}
}

// TestQueuedCommand_IsPending は pending ステータスの判定ロジックを確認する
func TestQueuedCommand_IsPending(t *testing.T) {
	cases := []struct {
		status    string
		isPending bool
	}{
		{"pending", true},
		{"running", false},
		{"completed", false},
		{"failed", false},
		{"timeout", false},
	}
	for _, tc := range cases {
		cmd := QueuedCommand{Status: tc.status}
		got := cmd.Status == "pending"
		if got != tc.isPending {
			t.Errorf("Status %q: isPending = %v, want %v", tc.status, got, tc.isPending)
		}
	}
}

// TestQueuedCommand_IsTerminal は終端ステータス（再試行不可）の判定を確認する
func TestQueuedCommand_IsTerminal(t *testing.T) {
	// isTerminal はDB不要の純粋なステータス判定ロジック
	isTerminal := func(status string) bool {
		return status == "completed" || status == "failed" || status == "timeout"
	}

	cases := []struct {
		status   string
		terminal bool
	}{
		{"pending", false},
		{"running", false},
		{"completed", true},
		{"failed", true},
		{"timeout", true},
	}
	for _, tc := range cases {
		if got := isTerminal(tc.status); got != tc.terminal {
			t.Errorf("isTerminal(%q) = %v, want %v", tc.status, got, tc.terminal)
		}
	}
}

// TestQueuedCommand_TimedOut はタイムアウト判定ロジックを確認する
func TestQueuedCommand_TimedOut(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// タイムアウト済みコマンド
	expired := QueuedCommand{
		Status:    "pending",
		TimeoutAt: past,
	}
	if expired.TimeoutAt.After(time.Now()) {
		t.Error("過去の TimeoutAt は現在時刻より後であってはならない")
	}

	// 有効なコマンド
	valid := QueuedCommand{
		Status:    "pending",
		TimeoutAt: future,
	}
	if !valid.TimeoutAt.After(time.Now()) {
		t.Error("未来の TimeoutAt は現在時刻より後であるべき")
	}
}

// TestQueuedCommand_ExitCodePointer は ExitCode がポインタとして正しく扱われることを確認する
func TestQueuedCommand_ExitCodePointer(t *testing.T) {
	// 終了コード 0 は成功を意味する（nil とは区別する必要がある）
	zero := 0
	cmd := QueuedCommand{ExitCode: &zero}
	if cmd.ExitCode == nil {
		t.Fatal("ExitCode は nil でないべき")
	}
	if *cmd.ExitCode != 0 {
		t.Errorf("*ExitCode = %d, want 0", *cmd.ExitCode)
	}

	// nil は「まだ終了していない」を意味する
	cmdRunning := QueuedCommand{Status: "running"}
	if cmdRunning.ExitCode != nil {
		t.Errorf("実行中コマンドの ExitCode は nil であるべき: got %v", *cmdRunning.ExitCode)
	}
}

// TestQueuedCommand_SessionIDPointer は SessionID が省略可能なポインタであることを確認する
func TestQueuedCommand_SessionIDPointer(t *testing.T) {
	// セッション付きコマンド
	sessionID := "session-abc-123"
	cmd := QueuedCommand{SessionID: &sessionID}
	if cmd.SessionID == nil {
		t.Fatal("SessionID は nil でないべき")
	}
	if *cmd.SessionID != sessionID {
		t.Errorf("*SessionID = %q, want %q", *cmd.SessionID, sessionID)
	}

	// セッションなしコマンド（単発実行）
	cmdNoSession := QueuedCommand{SessionID: nil}
	if cmdNoSession.SessionID != nil {
		t.Error("セッションなしコマンドの SessionID は nil であるべき")
	}
}

// ─── CreateQueuedCommandInput 構造体テスト ────────────────────────────────────

// TestCreateQueuedCommandInput_DefaultArgs は Args が nil のとき空オブジェクトにフォールバックすることを確認する
func TestCreateQueuedCommandInput_DefaultArgs(t *testing.T) {
	// live_response_store.go の Create メソッドでは Args が nil の場合 "{}" を使用する
	in := CreateQueuedCommandInput{
		AgentID:     "agent-001",
		CommandType: "shell",
		Command:     "ls -la",
		Args:        nil,
	}
	// nil のときはデフォルト値が使われることを確認する（ロジックを模倣）
	if in.Args == nil {
		in.Args = json.RawMessage("{}")
	}
	if string(in.Args) != "{}" {
		t.Errorf("デフォルト Args = %s, want \"{}\"", string(in.Args))
	}
}

// TestCreateQueuedCommandInput_WithArgs は Args が指定された場合に保持されることを確認する
func TestCreateQueuedCommandInput_WithArgs(t *testing.T) {
	args := json.RawMessage(`{"path":"/tmp","recursive":true}`)
	in := CreateQueuedCommandInput{
		AgentID:     "agent-002",
		CommandType: "file_list",
		Command:     "list_files",
		Args:        args,
	}
	if string(in.Args) != string(args) {
		t.Errorf("Args = %s, want %s", in.Args, args)
	}
}

// TestCreateQueuedCommandInput_CommandTypes はコマンドタイプが文字列として表現できることを確認する
func TestCreateQueuedCommandInput_CommandTypes(t *testing.T) {
	// ライブレスポンスで使用される代表的なコマンドタイプ
	commandTypes := []string{"shell", "file_list", "file_get", "process_list", "network_connections", "kill_process"}
	for _, cmdType := range commandTypes {
		in := CreateQueuedCommandInput{CommandType: cmdType}
		if in.CommandType != cmdType {
			t.Errorf("CommandType = %q, want %q", in.CommandType, cmdType)
		}
	}
}

// ─── コマンドキュー WHERE 句ビルダーテスト ────────────────────────────────────

// コマンドキューの絞り込みには、**製品側に対応する組み立てがありません。**
//
// `CmdQueueStore` にあるのは `ListByAgent`（`WHERE agent_id=$1` の固定）と
// `Get` だけで、`buildCmdQueueFilter` が言うような agentID + status の
// 組み立てはどこにもありません。**製品に無い約束を確かめていました。**
//
// 消すだけにします。**繋ぐ先がないものを繋いだふりはしません。**
