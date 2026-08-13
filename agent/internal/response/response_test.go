// Package response — ユニットテスト
// コマンド型・ヘルパー関数・アクションパースロジックをテストする。
// ネットワーク接続・プロセスキル・実際のファイル移動は行わない。
package response

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/edr-platform/agent/internal/collector"
)

// ─── extractIP ────────────────────────────────────────────────

// TestExtractIP はURLからホスト名/IPを正しく抽出することを確認する。
func TestExtractIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"HTTPスキーム付きURL", "http://10.0.0.1:8080", "10.0.0.1"},
		{"HTTPSスキーム付きURL", "https://edr-server.local:443", "edr-server.local"},
		{"パスなしURL", "http://192.168.1.100", "192.168.1.100"},
		{"ホスト名のみ", "edr-server", "edr-server"},
		{"空文字列", "", ""},
		{"スキームなしIPポート", "10.0.0.1:9000", "10.0.0.1:9000"}, // url.Parseが認識しない形式
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractIP(tc.input)
			if got != tc.want {
				t.Errorf("extractIP(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── IsolateCmd フィールド確認 ────────────────────────────────

// TestIsolateCmd_Fields はIsalateCmdのフィールドが正しく設定されることを確認する。
func TestIsolateCmd_Fields(t *testing.T) {
	tests := []struct {
		name       string
		commandID  string
		reason     string
		alertID    string
		allowedIPs []string
	}{
		{
			name:       "完全なコマンド",
			commandID:  "cmd-001",
			reason:     "Ransomware detected",
			alertID:    "alert-999",
			allowedIPs: []string{"10.0.0.1", "192.168.1.1"},
		},
		{
			name:       "AllowedIPsなし",
			commandID:  "cmd-002",
			reason:     "Suspicious activity",
			alertID:    "alert-100",
			allowedIPs: nil,
		},
		{
			name:       "理由なし",
			commandID:  "cmd-003",
			reason:     "",
			alertID:    "",
			allowedIPs: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := IsolateCmd{
				CommandID:  tc.commandID,
				Reason:     tc.reason,
				AlertID:    tc.alertID,
				AllowedIPs: tc.allowedIPs,
			}
			if cmd.CommandID != tc.commandID {
				t.Errorf("CommandID = %q, want %q", cmd.CommandID, tc.commandID)
			}
			if cmd.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", cmd.Reason, tc.reason)
			}
		})
	}
}

// ─── KillProcessCmd フィールド確認 ────────────────────────────

// TestKillProcessCmd_Fields はKillProcessCmdのフィールドを確認する。
func TestKillProcessCmd_Fields(t *testing.T) {
	cmd := KillProcessCmd{
		CommandID:   "kill-001",
		PID:         4567,
		ProcessName: "malware.exe",
		Reason:      "High severity detection",
	}

	if cmd.PID != 4567 {
		t.Errorf("PID = %d, want 4567", cmd.PID)
	}
	if cmd.ProcessName != "malware.exe" {
		t.Errorf("ProcessName = %q, want \"malware.exe\"", cmd.ProcessName)
	}
	if cmd.Reason == "" {
		t.Error("Reason が空")
	}
}

// ─── QuarantineFileCmd フィールド確認 ─────────────────────────

// TestQuarantineFileCmd_Fields はQuarantineFileCmdのフィールドを確認する。
func TestQuarantineFileCmd_Fields(t *testing.T) {
	tests := []struct {
		name      string
		commandID string
		path      string
		reason    string
		alertID   string
	}{
		{"Windowsパス", "qf-001", `C:\Temp\evil.exe`, "Malicious file", "alert-001"},
		{"Linuxパス", "qf-002", "/tmp/backdoor.sh", "Script detected", "alert-002"},
		{"パスなし", "qf-003", "", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := QuarantineFileCmd{
				CommandID: tc.commandID,
				Path:      tc.path,
				Reason:    tc.reason,
				AlertID:   tc.alertID,
			}
			if cmd.Path != tc.path {
				t.Errorf("Path = %q, want %q", cmd.Path, tc.path)
			}
			if cmd.AlertID != tc.alertID {
				t.Errorf("AlertID = %q, want %q", cmd.AlertID, tc.alertID)
			}
		})
	}
}

// ─── RestoreFileCmd フィールド確認 ────────────────────────────

// TestRestoreFileCmd_Fields はRestoreFileCmdのフィールドを確認する。
func TestRestoreFileCmd_Fields(t *testing.T) {
	cmd := RestoreFileCmd{
		CommandID:    "restore-001",
		QuarantineID: "quar-abc-123",
		RestorePath:  "/home/user/safe_file.txt",
	}

	if cmd.QuarantineID != "quar-abc-123" {
		t.Errorf("QuarantineID = %q, want \"quar-abc-123\"", cmd.QuarantineID)
	}
	if cmd.RestorePath != "/home/user/safe_file.txt" {
		t.Errorf("RestorePath = %q, want \"/home/user/safe_file.txt\"", cmd.RestorePath)
	}
}

// ─── LiveResponseStartPayload JSON 解析 ───────────────────────

// TestLiveResponseStartPayload_Unmarshal はJSONデシリアライズを確認する。
func TestLiveResponseStartPayload_Unmarshal(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantType     string
		wantSession  string
		wantCallback string
	}{
		{
			name:         "完全なペイロード",
			input:        `{"type":"live_response","session_id":"sess-001","token":"tok-abc","callback_url":"https://edr-server/api/v1"}`,
			wantType:     "live_response",
			wantSession:  "sess-001",
			wantCallback: "https://edr-server/api/v1",
		},
		{
			name:         "最小ペイロード",
			input:        `{"type":"live_response","session_id":"s-999","token":"t","callback_url":"http://localhost"}`,
			wantType:     "live_response",
			wantSession:  "s-999",
			wantCallback: "http://localhost",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p LiveResponseStartPayload
			if err := json.Unmarshal([]byte(tc.input), &p); err != nil {
				t.Fatalf("Unmarshalエラー: %v", err)
			}
			if p.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", p.Type, tc.wantType)
			}
			if p.SessionID != tc.wantSession {
				t.Errorf("SessionID = %q, want %q", p.SessionID, tc.wantSession)
			}
			if p.CallbackURL != tc.wantCallback {
				t.Errorf("CallbackURL = %q, want %q", p.CallbackURL, tc.wantCallback)
			}
		})
	}
}

// TestLiveResponseStartPayload_Marshal はシリアライズが正しいキーを出力することを確認する。
func TestLiveResponseStartPayload_Marshal(t *testing.T) {
	p := LiveResponseStartPayload{
		Type:        "live_response",
		SessionID:   "sess-xyz",
		Token:       "bearer-token-123",
		CallbackURL: "https://edr.example.com/api/v1",
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshalエラー: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("再デシリアライズエラー: %v", err)
	}

	requiredFields := []string{"type", "session_id", "token", "callback_url"}
	for _, field := range requiredFields {
		if _, ok := out[field]; !ok {
			t.Errorf("JSONに%qキーがない", field)
		}
	}
}

// ─── Manager コマンドディスパッチ ─────────────────────────────

// TestManager_ExecuteCommand_UnknownType は未知のコマンドタイプが無視されることを確認する。
// (エラーを返さないことを確認する)
func TestManager_ExecuteCommand_UnknownType(t *testing.T) {
	m, err := NewManagerWithQuarantineDir("10.0.0.1", t.TempDir())
	if err != nil {
		t.Fatalf("NewManager失敗: %v", err)
	}
	err = m.ExecuteCommand(context.Background(), "nonexistent_command", []byte(`{}`))
	if err != nil {
		t.Errorf("未知コマンドタイプでエラーが返された: %v", err)
	}
}

// TestManager_ExecuteCommand_KillProcess_InvalidPayload は不正なJSONペイロードでエラーを返すことを確認する。
func TestManager_ExecuteCommand_KillProcess_InvalidPayload(t *testing.T) {
	m, err := NewManagerWithQuarantineDir("10.0.0.1", t.TempDir())
	if err != nil {
		t.Fatalf("NewManager失敗: %v", err)
	}
	err = m.ExecuteCommand(context.Background(), "kill_process", []byte(`{invalid json}`))
	if err == nil {
		t.Error("不正なJSONペイロードでエラーが返されなかった")
	}
}

// TestManager_ExecuteCommand_QuarantineFile_InvalidPayload は不正なJSONペイロードでエラーを返すことを確認する。
func TestManager_ExecuteCommand_QuarantineFile_InvalidPayload(t *testing.T) {
	m, err := NewManagerWithQuarantineDir("10.0.0.1", t.TempDir())
	if err != nil {
		t.Fatalf("NewManager失敗: %v", err)
	}
	err = m.ExecuteCommand(context.Background(), "quarantine_file", []byte(`not-json`))
	if err == nil {
		t.Error("不正なJSONペイロードでエラーが返されなかった")
	}
}

// ─── Executor — モックを使ったハンドラーテスト ────────────────

// mockAckSender はAckSenderインターフェースのモック実装。
type mockAckSender struct {
	calls   int
	success bool
	errMsg  string
}

func (m *mockAckSender) SendAck(_ context.Context, _ string, success bool, errMsg string, _ []byte) error {
	m.calls++
	m.success = success
	m.errMsg = errMsg
	return nil
}

// mockIsolationManager はIsolationManagerインターフェースのモック実装。
type mockIsolationManager struct {
	isolated     bool
	isolateErr   error
	unisolateErr error
	// verifyLies が true なら、Isolate が成功しても実態は「入っていない」を返す。
	// 「コマンドは成功したがルールが無い」を再現するため。
	verifyLies bool
	verifyErr  error
}

func (m *mockIsolationManager) VerifyIsolation() (bool, error) {
	if m.verifyErr != nil {
		return false, m.verifyErr
	}
	if m.verifyLies {
		return false, nil
	}
	return m.isolated, nil
}

func (m *mockIsolationManager) Isolate(_ []string, _ []uint16) error {
	if m.isolateErr != nil {
		return m.isolateErr
	}
	m.isolated = true
	return nil
}

func (m *mockIsolationManager) Unisolate() error {
	if m.unisolateErr != nil {
		return m.unisolateErr
	}
	m.isolated = false
	return nil
}

func (m *mockIsolationManager) IsIsolated() bool {
	return m.isolated
}

// mockProcessManager はProcessManagerインターフェースのモック実装。
type mockProcessManager struct {
	killErr error
	killed  []uint32
}

func (m *mockProcessManager) Kill(pid uint32) error {
	if m.killErr != nil {
		return m.killErr
	}
	m.killed = append(m.killed, pid)
	return nil
}

// mockFileQuarantine はFileQuarantineインターフェースのモック実装。
type mockFileQuarantine struct {
	quarantineID  string
	quarantineErr error
	restoreErr    error
}

func (m *mockFileQuarantine) Quarantine(path string) (string, error) {
	if m.quarantineErr != nil {
		return "", m.quarantineErr
	}
	if m.quarantineID == "" {
		return "quar-mock-001", nil
	}
	return m.quarantineID, nil
}

func (m *mockFileQuarantine) Restore(quarantineID, restorePath string) error {
	return m.restoreErr
}

func (m *mockFileQuarantine) List() ([]collector.QuarantinedFile, error) {
	return nil, nil
}

// TestExecutor_KillProcess_Success はKillProcessが成功する場合を確認する。
func TestExecutor_KillProcess_Success(t *testing.T) {
	ack := &mockAckSender{}
	pm := &mockProcessManager{}
	exec := NewExecutor(
		&mockIsolationManager{},
		pm,
		&mockFileQuarantine{},
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.KillProcess(context.Background(), KillProcessCmd{
		CommandID:   "kill-001",
		PID:         1234,
		ProcessName: "malware.exe",
		Reason:      "threat detected",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("KillProcess成功時にack.successがfalse")
	}
	if len(pm.killed) != 1 || pm.killed[0] != 1234 {
		t.Errorf("killed = %v, want [1234]", pm.killed)
	}
}

// TestExecutor_KillProcess_Error はKillProcessが失敗する場合を確認する。
func TestExecutor_KillProcess_Error(t *testing.T) {
	ack := &mockAckSender{}
	pm := &mockProcessManager{killErr: errors.New("permission denied")}
	exec := NewExecutor(
		&mockIsolationManager{},
		pm,
		&mockFileQuarantine{},
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.KillProcess(context.Background(), KillProcessCmd{
		CommandID: "kill-002",
		PID:       9999,
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if ack.success {
		t.Error("KillProcess失敗時にack.successがtrue")
	}
	if ack.errMsg == "" {
		t.Error("エラーメッセージが空")
	}
}

// TestExecutor_Isolate_Success はIsolateが成功する場合を確認する。
func TestExecutor_Isolate_Success(t *testing.T) {
	ack := &mockAckSender{}
	iso := &mockIsolationManager{}
	exec := NewExecutor(
		iso,
		&mockProcessManager{},
		&mockFileQuarantine{},
		"agent-001",
		"http://10.0.0.1:8080",
		ack,
	)

	exec.Isolate(context.Background(), IsolateCmd{
		CommandID:  "iso-001",
		Reason:     "Ransomware detected",
		AlertID:    "alert-999",
		AllowedIPs: []string{"10.0.0.1"},
	})

	if !iso.isolated {
		t.Error("Isolate成功後にisolated=falseになっている")
	}
	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("Isolate成功時にack.successがfalse")
	}
}

// TestExecutor_Isolate_Error はIsolateが失敗する場合を確認する。
func TestExecutor_Isolate_Error(t *testing.T) {
	ack := &mockAckSender{}
	iso := &mockIsolationManager{isolateErr: errors.New("iptables error")}
	exec := NewExecutor(
		iso,
		&mockProcessManager{},
		&mockFileQuarantine{},
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.Isolate(context.Background(), IsolateCmd{
		CommandID: "iso-fail",
		Reason:    "test",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if ack.success {
		t.Error("Isolate失敗時にack.successがtrue")
	}
}

// TestExecutor_Unisolate_Success はUnisolateが成功する場合を確認する。
func TestExecutor_Unisolate_Success(t *testing.T) {
	ack := &mockAckSender{}
	iso := &mockIsolationManager{isolated: true}
	exec := NewExecutor(
		iso,
		&mockProcessManager{},
		&mockFileQuarantine{},
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.Unisolate(context.Background(), UnisolateCmd{
		CommandID: "uniso-001",
		Reason:    "Investigation complete",
	})

	if iso.isolated {
		t.Error("Unisolate後にisolated=trueになっている")
	}
	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("Unisolate成功時にack.successがfalse")
	}
}

// TestExecutor_QuarantineFile_Success はQuarantineFileが成功する場合を確認する。
func TestExecutor_QuarantineFile_Success(t *testing.T) {
	ack := &mockAckSender{}
	quar := &mockFileQuarantine{quarantineID: "quar-xyz-789"}
	exec := NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		quar,
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.QuarantineFile(context.Background(), QuarantineFileCmd{
		CommandID: "qf-001",
		Path:      "/tmp/evil.exe",
		Reason:    "Detected malicious file",
		AlertID:   "alert-111",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("QuarantineFile成功時にack.successがfalse")
	}
}

// TestExecutor_QuarantineFile_Error はQuarantineFileが失敗する場合を確認する。
func TestExecutor_QuarantineFile_Error(t *testing.T) {
	ack := &mockAckSender{}
	quar := &mockFileQuarantine{quarantineErr: errors.New("file not found")}
	exec := NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		quar,
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.QuarantineFile(context.Background(), QuarantineFileCmd{
		CommandID: "qf-fail",
		Path:      "/nonexistent/file.exe",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if ack.success {
		t.Error("QuarantineFile失敗時にack.successがtrue")
	}
}

// TestExecutor_RestoreFile_Success はRestoreFileが成功する場合を確認する。
func TestExecutor_RestoreFile_Success(t *testing.T) {
	ack := &mockAckSender{}
	quar := &mockFileQuarantine{}
	exec := NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		quar,
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.RestoreFile(context.Background(), RestoreFileCmd{
		CommandID:    "restore-001",
		QuarantineID: "quar-abc",
		RestorePath:  "/home/user/restored.exe",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("RestoreFile成功時にack.successがfalse")
	}
}

// TestExecutor_RestoreFile_Error はRestoreFileが失敗する場合を確認する。
func TestExecutor_RestoreFile_Error(t *testing.T) {
	ack := &mockAckSender{}
	quar := &mockFileQuarantine{restoreErr: errors.New("quarantine ID not found")}
	exec := NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		quar,
		"agent-001",
		"http://edr:8080",
		ack,
	)

	exec.RestoreFile(context.Background(), RestoreFileCmd{
		CommandID:    "restore-fail",
		QuarantineID: "nonexistent-quar-id",
	})

	if ack.calls != 1 {
		t.Errorf("Ack呼び出し回数 = %d, want 1", ack.calls)
	}
	if ack.success {
		t.Error("RestoreFile失敗時にack.successがtrue")
	}
	if ack.errMsg == "" {
		t.Error("エラーメッセージが空")
	}
}

// TestExecutor_NilAck はAckSenderがnilでもパニックしないことを確認する。
func TestExecutor_NilAck(t *testing.T) {
	exec := NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		&mockFileQuarantine{},
		"agent-001",
		"http://edr:8080",
		nil, // AckSenderをnilに設定
	)

	// パニックが発生しないことを確認する
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil AckSender でパニックが発生した: %v", r)
		}
	}()

	exec.KillProcess(context.Background(), KillProcessCmd{
		CommandID: "kill-nil-ack",
		PID:       1,
	})
}
