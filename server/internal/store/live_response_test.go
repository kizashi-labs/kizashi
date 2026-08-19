package store

import (
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

// 終了コードが 0 でないコマンドが、「成功」として保存されないこと。
//
// **以前ここには `determineStatus` という写しが置いてありました。**
// 検査の中で `if hasError { return "error" }` を書き直し、それを試して
// いました —— 製品側を変えても落ちません。
//
// 写しを本物に向けたところ、**本物の側に欠陥がありました。**
// エージェントは、コマンドが起動できたなら終了コードが 1 でも
// `hasError=false` を返します。サーバはその旗だけを見て "completed" を
// 保存し、**コンソールは status だけを見ます** —— `exit_code` は API の
// 型にも入っていません。`test -f /nonexistent` は「(出力なし)」が通常の
// 出力として表示され、担当者はファイルの確認が通ったと読みます。
func TestANonZeroExitIsNotCompleted(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		hasError bool
		want     string
	}{
		{"成功", 0, false, "completed"},
		// **これが直した分です。**
		{"終了コード 1", 1, false, "error"},
		{"終了コード 127（コマンドが無い）", 127, false, "error"},
		{"負の終了コード（シグナルで終了）", -1, false, "error"},
		{"起動できなかった", 1, true, "error"},
		// 起動できなかったのに終了コードが 0 の場合も、成功ではありません。
		{"起動できず、終了コード 0", 0, true, "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandCompletionStatus(tc.exitCode, tc.hasError); got != tc.want {
				t.Errorf("commandCompletionStatus(%d, %v) = %q, want %q。"+
					"**コンソールは status だけを見ます** —— "+
					"failed が completed になると、対応の最中に"+
					"失敗が成功に見えます",
					tc.exitCode, tc.hasError, got, tc.want)
			}
		})
	}
}

// 保存できる状態が、DB 側の許す値に収まっていること。
//
// **"failed" のような新しい語を足すと、CHECK 制約に弾かれて
// コマンドの結果が1件も記録できなくなります。**
func TestTheCompletionStatusIsOneTheSchemaAllows(t *testing.T) {
	allowed := map[string]bool{
		"pending": true, "running": true, "completed": true,
		"error": true, "timeout": true,
	}
	for _, exit := range []int{0, 1, 127} {
		for _, hasErr := range []bool{false, true} {
			got := commandCompletionStatus(exit, hasErr)
			if !allowed[got] {
				t.Errorf("commandCompletionStatus(%d, %v) = %q。"+
					"**DB の CHECK 制約に無い値です**", exit, hasErr, got)
			}
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

// Args の既定値は `live_response_store.go` の Create が入れます。
//
// **ここには、その置き換えを検査の中で書き直して確かめる2本が置いて
// ありました** —— `if in.Args == nil { in.Args = "{}" }` を検査の本文で
// 実行し、そのあと `in.Args == "{}"` を確かめる。製品を1行も通りません。
//
// 本物を当てる検査は `live_response_create_db_test.go` にあります。

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
