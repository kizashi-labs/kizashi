// Package collector — ユニットテスト
// イベント型の分類・ヘルパー関数・FIM除外ロジックをテストする。
// ネットワーク接続・ファイルシステム実装は不要。
package collector

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── ProcessEvent フィールド検証 ──────────────────────────────

// TestProcessEvent_ZeroValue はゼロ値の構造体が正しく初期化されることを確認する。
func TestProcessEvent_ZeroValue(t *testing.T) {
	var e ProcessEvent
	if e.PID != 0 {
		t.Errorf("ゼロ値PID = %d, want 0", e.PID)
	}
	if e.Action != "" {
		t.Errorf("ゼロ値Action = %q, want \"\"", e.Action)
	}
	if !e.Timestamp.IsZero() {
		// time.Timeのゼロ値を確認
		if e.Timestamp != (time.Time{}) {
			t.Errorf("ゼロ値Timestamp が空でない: %v", e.Timestamp)
		}
	}
}

// TestProcessEvent_Actions はProcessEventのActionフィールドに期待値を設定できることを確認する。
func TestProcessEvent_Actions(t *testing.T) {
	validActions := []string{"create", "terminate", "inject", "hollow"}
	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			e := ProcessEvent{
				ID:          "test-001",
				PID:         1234,
				ProcessName: "test.exe",
				Action:      action,
				Timestamp:   time.Now(),
			}
			if e.Action != action {
				t.Errorf("Action = %q, want %q", e.Action, action)
			}
		})
	}
}

// TestProcessEvent_JSONSerialization はJSONシリアライズ・デシリアライズを確認する。
func TestProcessEvent_JSONSerialization(t *testing.T) {
	original := ProcessEvent{
		ID:          "proc-001",
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		PID:         4567,
		PPID:        1,
		ProcessName: "malware.exe",
		CommandLine: "malware.exe --silent",
		ImagePath:   `C:\Temp\malware.exe`,
		Username:    "SYSTEM",
		Action:      "create",
		Hashes: FileHashes{
			MD5:    "d41d8cd98f00b204e9800998ecf8427e",
			SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshalエラー: %v", err)
	}

	var restored ProcessEvent
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshalエラー: %v", err)
	}

	if restored.ID != original.ID {
		t.Errorf("ID = %q, want %q", restored.ID, original.ID)
	}
	if restored.PID != original.PID {
		t.Errorf("PID = %d, want %d", restored.PID, original.PID)
	}
	if restored.ProcessName != original.ProcessName {
		t.Errorf("ProcessName = %q, want %q", restored.ProcessName, original.ProcessName)
	}
	if restored.Hashes.SHA256 != original.Hashes.SHA256 {
		t.Errorf("SHA256 = %q, want %q", restored.Hashes.SHA256, original.Hashes.SHA256)
	}
}

// ─── FileEvent フィールド検証 ─────────────────────────────────

// TestFileEvent_Actions はFileEventの有効なActionを確認する。
func TestFileEvent_Actions(t *testing.T) {
	validActions := []string{"create", "modify", "delete", "rename", "execute"}
	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			e := FileEvent{
				ID:        "file-001",
				Path:      "/etc/passwd",
				Action:    action,
				Timestamp: time.Now(),
			}
			if e.Action != action {
				t.Errorf("FileEvent.Action = %q, want %q", e.Action, action)
			}
		})
	}
}

// TestFileEvent_RenameFields はリネームイベントでOldPathが設定されることを確認する。
func TestFileEvent_RenameFields(t *testing.T) {
	e := FileEvent{
		ID:        "rename-001",
		Path:      "/home/user/newname.txt",
		OldPath:   "/home/user/oldname.txt",
		Action:    "rename",
		Timestamp: time.Now(),
	}
	if e.OldPath == "" {
		t.Error("リネームイベントのOldPathが空")
	}
	if e.OldPath == e.Path {
		t.Error("OldPathとPathが同じ値")
	}
}

// ─── NetworkEvent フィールド検証 ──────────────────────────────

// TestNetworkEvent_Protocols はNetworkEventの有効なProtocolを確認する。
func TestNetworkEvent_Protocols(t *testing.T) {
	tests := []struct {
		protocol string
	}{
		{"tcp"},
		{"udp"},
		{"icmp"},
	}
	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			e := NetworkEvent{
				ID:        "net-001",
				SrcIP:     "192.168.1.100",
				DstIP:     "10.0.0.1",
				Protocol:  tc.protocol,
				Direction: "outbound",
				Timestamp: time.Now(),
			}
			if e.Protocol != tc.protocol {
				t.Errorf("Protocol = %q, want %q", e.Protocol, tc.protocol)
			}
		})
	}
}

// TestNetworkEvent_Directions はNetworkEventの有効なDirectionを確認する。
func TestNetworkEvent_Directions(t *testing.T) {
	for _, dir := range []string{"inbound", "outbound"} {
		e := NetworkEvent{Direction: dir}
		if e.Direction != dir {
			t.Errorf("Direction = %q, want %q", e.Direction, dir)
		}
	}
}

// ─── RegistryEvent フィールド検証 ────────────────────────────

// TestRegistryEvent_Actions はRegistryEventの有効なActionを確認する。
func TestRegistryEvent_Actions(t *testing.T) {
	validActions := []string{"create", "modify", "delete", "query"}
	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			e := RegistryEvent{
				ID:          "reg-001",
				KeyPath:     `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
				ValueName:   "Persistence",
				ValueData:   `C:\malware.exe`,
				Action:      action,
				PID:         999,
				ProcessName: "malware.exe",
				Timestamp:   time.Now(),
			}
			if e.Action != action {
				t.Errorf("RegistryEvent.Action = %q, want %q", e.Action, action)
			}
		})
	}
}

// ─── AuthEvent フィールド検証 ─────────────────────────────────

// TestAuthEvent_Actions はAuthEventの有効なActionを確認する。
func TestAuthEvent_Actions(t *testing.T) {
	validActions := []string{"login", "logout", "privilege", "failed"}
	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			e := AuthEvent{
				ID:         "auth-001",
				Username:   "admin",
				Action:     action,
				Success:    action != "failed",
				SourceIP:   "10.0.0.5",
				AuthMethod: "password",
				Timestamp:  time.Now(),
			}
			if e.Action != action {
				t.Errorf("AuthEvent.Action = %q, want %q", e.Action, action)
			}
		})
	}
}

// TestAuthEvent_FailedLogin は失敗ログインイベントのフィールドを確認する。
func TestAuthEvent_FailedLogin(t *testing.T) {
	e := AuthEvent{
		ID:         "auth-fail-001",
		Username:   "root",
		Action:     "failed",
		Success:    false,
		SourceIP:   "203.0.113.1",
		AuthMethod: "ssh",
		FailReason: "Invalid credentials",
		Timestamp:  time.Now(),
	}

	if e.Success {
		t.Error("失敗ログインイベントでSuccessがtrueになっている")
	}
	if e.FailReason == "" {
		t.Error("失敗ログインイベントのFailReasonが空")
	}
}

// ─── FileHashes 型確認 ────────────────────────────────────────

// TestFileHashes_Fields はFileHashesの各フィールドに値を設定できることを確認する。
func TestFileHashes_Fields(t *testing.T) {
	h := FileHashes{
		MD5:    "d41d8cd98f00b204e9800998ecf8427e",
		SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	if len(h.MD5) != 32 {
		t.Errorf("MD5の長さ = %d, want 32", len(h.MD5))
	}
	if len(h.SHA1) != 40 {
		t.Errorf("SHA1の長さ = %d, want 40", len(h.SHA1))
	}
	if len(h.SHA256) != 64 {
		t.Errorf("SHA256の長さ = %d, want 64", len(h.SHA256))
	}
}

// ─── isExcluded ───────────────────────────────────────────────

// TestIsExcluded_GlobPattern はグロブパターンによる除外を確認する。
func TestIsExcluded_GlobPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{
			name:     "*.logパターンに一致",
			path:     "/var/log/app.log",
			patterns: []string{"*.log"},
			want:     true,
		},
		{
			name:     "パターン不一致",
			path:     "/etc/passwd",
			patterns: []string{"*.log"},
			want:     false,
		},
		{
			name:     "パターンなし",
			path:     "/etc/passwd",
			patterns: []string{},
			want:     false,
		},
		{
			name:     "プレフィックス一致",
			path:     "/tmp/evil.exe",
			patterns: []string{"/tmp/"},
			want:     true,
		},
		{
			name:     "複数パターン（一つが一致）",
			path:     "/etc/shadow",
			patterns: []string{"*.log", "*.tmp", "shadow"},
			want:     true,
		},
		{
			name:     "完全一致",
			path:     "/etc/crontab",
			patterns: []string{"/etc/crontab"},
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isExcluded(tc.path, tc.patterns)
			if got != tc.want {
				t.Errorf("isExcluded(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

// ─── QuarantinedFile 型確認 ───────────────────────────────────

// TestQuarantinedFile_Fields はQuarantinedFileの各フィールドを確認する。
func TestQuarantinedFile_Fields(t *testing.T) {
	now := time.Now()
	qf := QuarantinedFile{
		ID:            "quar-001",
		OriginalPath:  "/tmp/malware.exe",
		QuarantinedAt: now,
		Hashes: FileHashes{
			SHA256: "abc123",
		},
		AlertID: "alert-999",
	}

	if qf.ID == "" {
		t.Error("QuarantinedFile.ID が空")
	}
	if qf.OriginalPath == "" {
		t.Error("QuarantinedFile.OriginalPath が空")
	}
	if qf.QuarantinedAt.IsZero() {
		t.Error("QuarantinedFile.QuarantinedAt がゼロ値")
	}
}

// ─── DeviceCollector 初期化 ───────────────────────────────────

// TestNewDeviceCollector_DefaultInterval はデフォルトインターバルが10秒になることを確認する。
func TestNewDeviceCollector_DefaultInterval(t *testing.T) {
	// nilセンダーでも初期化だけなら問題ない
	dc := NewDeviceCollector(nil, "agent-001", 0)
	if dc == nil {
		t.Fatal("NewDeviceCollector が nil を返した")
	}
	if dc.interval != 10*time.Second {
		t.Errorf("デフォルトインターバル = %v, want 10s", dc.interval)
	}
}

// TestNewDeviceCollector_CustomInterval はカスタムインターバルが設定されることを確認する。
func TestNewDeviceCollector_CustomInterval(t *testing.T) {
	dc := NewDeviceCollector(nil, "agent-002", 30*time.Second)
	if dc.interval != 30*time.Second {
		t.Errorf("カスタムインターバル = %v, want 30s", dc.interval)
	}
}

// TestNewDeviceCollector_AgentID はagentIDが正しく設定されることを確認する。
func TestNewDeviceCollector_AgentID(t *testing.T) {
	dc := NewDeviceCollector(nil, "test-agent-xyz", 5*time.Second)
	if dc.agentID != "test-agent-xyz" {
		t.Errorf("agentID = %q, want \"test-agent-xyz\"", dc.agentID)
	}
}

// TestNewDeviceCollector_KnownMapInitialized はknownマップが初期化されることを確認する。
func TestNewDeviceCollector_KnownMapInitialized(t *testing.T) {
	dc := NewDeviceCollector(nil, "agent-003", 0)
	if dc.known == nil {
		t.Error("DeviceCollector.known が nil（初期化されていない）")
	}
	if len(dc.known) != 0 {
		t.Errorf("初期known件数 = %d, want 0", len(dc.known))
	}
}

// ─── DNSEvent 型確認 ──────────────────────────────────────────

// TestDNSEvent_Fields はDNSEventの各フィールドを確認する。
func TestDNSEvent_Fields(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		queryType string
		answers   []string
	}{
		{"Aレコード", "example.com", "A", []string{"93.184.216.34"}},
		{"AAAAレコード", "ipv6.example.com", "AAAA", []string{"2001:db8::1"}},
		{"MXレコード", "mail.example.com", "MX", []string{"10 mail.example.com."}},
		{"疑わしいドメイン", "c2server.malware.io", "A", []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := DNSEvent{
				ID:        "dns-001",
				Timestamp: time.Now(),
				Query:     tc.query,
				QueryType: tc.queryType,
				Answers:   tc.answers,
				PID:       1234,
			}
			if e.Query != tc.query {
				t.Errorf("Query = %q, want %q", e.Query, tc.query)
			}
			if e.QueryType != tc.queryType {
				t.Errorf("QueryType = %q, want %q", e.QueryType, tc.queryType)
			}
		})
	}
}
