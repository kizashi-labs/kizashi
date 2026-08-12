// Package updater — ユニットテスト
// HTTP通信・ファイルシステム操作を伴わない純粋関数・構造体のみをテストする。
package updater

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ─── UpdateInfo JSON デシリアライズ ───────────────────────────

// TestUpdateInfo_UnmarshalJSON はJSONデシリアライズが全フィールドを正しく設定することを確認する。
func TestUpdateInfo_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantURL     string
		wantCheck   string
		wantForce   bool
	}{
		{
			name:        "通常のアップデート情報",
			input:       `{"version":"1.2.3","url":"/downloads/edr-agent-linux-amd64","checksum":"sha256:abcdef123456","force_update":false}`,
			wantVersion: "1.2.3",
			wantURL:     "/downloads/edr-agent-linux-amd64",
			wantCheck:   "sha256:abcdef123456",
			wantForce:   false,
		},
		{
			name:        "強制アップデートフラグが真",
			input:       `{"version":"2.0.0","url":"https://cdn.example.com/agent","checksum":"sha256:deadbeef","force_update":true}`,
			wantVersion: "2.0.0",
			wantURL:     "https://cdn.example.com/agent",
			wantCheck:   "sha256:deadbeef",
			wantForce:   true,
		},
		{
			name:        "バージョンのみ（URLとチェックサムが空）",
			input:       `{"version":"0.9.1","url":"","checksum":"","force_update":false}`,
			wantVersion: "0.9.1",
			wantURL:     "",
			wantCheck:   "",
			wantForce:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var info UpdateInfo
			if err := json.Unmarshal([]byte(tc.input), &info); err != nil {
				t.Fatalf("Unmarshalエラー: %v", err)
			}
			if info.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", info.Version, tc.wantVersion)
			}
			if info.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", info.URL, tc.wantURL)
			}
			if info.Checksum != tc.wantCheck {
				t.Errorf("Checksum = %q, want %q", info.Checksum, tc.wantCheck)
			}
			if info.ForceUpdate != tc.wantForce {
				t.Errorf("ForceUpdate = %v, want %v", info.ForceUpdate, tc.wantForce)
			}
		})
	}
}

// TestUpdateInfo_MarshalJSON はシリアライズが期待するJSONキーを含むことを確認する。
func TestUpdateInfo_MarshalJSON(t *testing.T) {
	info := UpdateInfo{
		Version:     "3.1.4",
		URL:         "/dl/edr-agent",
		Checksum:    "sha256:cafebabe",
		ForceUpdate: true,
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshalエラー: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("再デシリアライズエラー: %v", err)
	}

	if out["version"] != "3.1.4" {
		t.Errorf("versionフィールド = %v, want \"3.1.4\"", out["version"])
	}
	if out["force_update"] != true {
		t.Errorf("force_updateフィールド = %v, want true", out["force_update"])
	}
	if out["checksum"] != "sha256:cafebabe" {
		t.Errorf("checksumフィールド = %v, want \"sha256:cafebabe\"", out["checksum"])
	}
}

// ─── New() コンストラクタ ─────────────────────────────────────

// TestNew_StripTrailingSlash はserverURLの末尾スラッシュが除去されることを確認する。
func TestNew_StripTrailingSlash(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"スラッシュあり", "https://edr-server.local:8443/", "https://edr-server.local:8443"},
		{"スラッシュなし", "https://edr-server.local:8443", "https://edr-server.local:8443"},
		{"複数スラッシュ", "https://edr-server.local///", "https://edr-server.local"},
		{"HTTPスキーム", "http://10.0.0.1:9000/", "http://10.0.0.1:9000"},
		{"スラッシュのみ", "/", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := New(tc.serverURL, "agent-001", "1.0.0", "/tmp")
			if u.serverURL != tc.want {
				t.Errorf("serverURL = %q, want %q", u.serverURL, tc.want)
			}
		})
	}
}

// TestNew_FieldsAreSet はNew()が全フィールドを正しく設定することを確認する。
func TestNew_FieldsAreSet(t *testing.T) {
	u := New("https://edr.corp.local:8443", "agent-xyz-123", "2.5.0", "/var/edr")

	if u.agentID != "agent-xyz-123" {
		t.Errorf("agentID = %q, want \"agent-xyz-123\"", u.agentID)
	}
	if u.currentVersion != "2.5.0" {
		t.Errorf("currentVersion = %q, want \"2.5.0\"", u.currentVersion)
	}
	if u.dataDir != "/var/edr" {
		t.Errorf("dataDir = %q, want \"/var/edr\"", u.dataDir)
	}
	if u.httpClient == nil {
		t.Error("httpClient が nil（初期化されていない）")
	}
}

// TestNew_HTTPClientNotNil はHTTPクライアントがnilでないことを確認する。
func TestNew_HTTPClientNotNil(t *testing.T) {
	u := New("https://edr.local", "a", "1.0", "/tmp")
	if u.httpClient == nil {
		t.Fatal("httpClient が nil")
	}
	if u.httpClient.Timeout == 0 {
		t.Error("httpClient.Timeout がゼロ（タイムアウト未設定）")
	}
}

// ─── チェックサム解析ロジック ─────────────────────────────────

// TestChecksumParsing は"sha256:"プレフィックス付きチェックサムの解析ロジックを確認する。
// Apply()内のロジックと同じ抽出処理を直接テストする。
func TestChecksumParsing(t *testing.T) {
	tests := []struct {
		name     string
		checksum string
		want     string
	}{
		{"プレフィックス付き", "sha256:abcdef1234567890", "abcdef1234567890"},
		{"プレフィックスなし（生ハッシュ）", "abcdef1234567890", "abcdef1234567890"},
		{"大文字プレフィックス", "SHA256:ABCDEF1234567890", "SHA256:ABCDEF1234567890"},
		{"空チェックサム", "", ""},
		{"sha256:のみ", "sha256:", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.checksum
			got = strings.TrimPrefix(got, "sha256:")
			if got != tc.want {
				t.Errorf("解析後チェックサム = %q, want %q", got, tc.want)
			}
		})
	}
}

// ─── 相対URLの解決ロジック ────────────────────────────────────

// TestRelativeURLResolution はApply()内の相対URLをserverURLで補完するロジックを確認する。
func TestRelativeURLResolution(t *testing.T) {
	serverURL := "https://edr-server.local:8443"

	tests := []struct {
		name    string
		rawURL  string
		wantURL string
	}{
		{
			name:    "相対パス（スラッシュ始まり）",
			rawURL:  "/downloads/edr-agent-linux-amd64",
			wantURL: "https://edr-server.local:8443/downloads/edr-agent-linux-amd64",
		},
		{
			name:    "絶対URL（そのまま）",
			rawURL:  "https://cdn.example.com/edr-agent",
			wantURL: "https://cdn.example.com/edr-agent",
		},
		{
			name:    "HTTPの絶対URL",
			rawURL:  "http://internal.mirror/edr-agent-v2",
			wantURL: "http://internal.mirror/edr-agent-v2",
		},
		{
			name:    "別の相対パス",
			rawURL:  "/api/v1/binaries/linux-amd64/latest",
			wantURL: "https://edr-server.local:8443/api/v1/binaries/linux-amd64/latest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			downloadURL := tc.rawURL
			if strings.HasPrefix(downloadURL, "/") {
				downloadURL = serverURL + downloadURL
			}
			if downloadURL != tc.wantURL {
				t.Errorf("解決後URL = %q, want %q", downloadURL, tc.wantURL)
			}
		})
	}
}

// ─── マーカーファイルのJSON形式 ───────────────────────────────

// TestMarkerFileFormat はupdate-pendingマーカーファイルが有効なJSON形式であることを確認する。
func TestMarkerFileFormat(t *testing.T) {
	newBinPath := "/var/edr/edr-agent.new"
	version := "1.5.2"
	timestamp := "2026-01-15T10:30:00Z"

	// Apply()内のマーカーコンテンツ生成ロジックと同一
	content := fmt.Sprintf(`{"new_binary":%q,"version":%q,"timestamp":%q}`,
		newBinPath, version, timestamp)

	var parsed map[string]string
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		t.Fatalf("マーカーファイルのJSONパース失敗: %v", err)
	}

	if parsed["new_binary"] != newBinPath {
		t.Errorf("new_binary = %q, want %q", parsed["new_binary"], newBinPath)
	}
	if parsed["version"] != version {
		t.Errorf("version = %q, want %q", parsed["version"], version)
	}
	if parsed["timestamp"] != timestamp {
		t.Errorf("timestamp = %q, want %q", parsed["timestamp"], timestamp)
	}
}

// TestMarkerFileFormat_SpecialChars はパスに特殊文字が含まれても正しくエスケープされることを確認する。
func TestMarkerFileFormat_SpecialChars(t *testing.T) {
	// Windowsスタイルのパス（バックスラッシュを含む）
	newBinPath := `C:\ProgramData\EDR\edr-agent.new.exe`
	version := "2.0.0"
	timestamp := "2026-03-23T00:00:00Z"

	content := fmt.Sprintf(`{"new_binary":%q,"version":%q,"timestamp":%q}`,
		newBinPath, version, timestamp)

	var parsed map[string]string
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		t.Fatalf("特殊文字含むパスのJSONパース失敗: %v", err)
	}

	if parsed["new_binary"] != newBinPath {
		t.Errorf("new_binary = %q, want %q", parsed["new_binary"], newBinPath)
	}
}

// ─── UpdateInfo ゼロ値 ────────────────────────────────────────

// TestUpdateInfo_ZeroValue はUpdateInfoのゼロ値フィールドを確認する。
func TestUpdateInfo_ZeroValue(t *testing.T) {
	var info UpdateInfo

	if info.Version != "" {
		t.Errorf("ゼロ値Version = %q, want \"\"", info.Version)
	}
	if info.URL != "" {
		t.Errorf("ゼロ値URL = %q, want \"\"", info.URL)
	}
	if info.Checksum != "" {
		t.Errorf("ゼロ値Checksum = %q, want \"\"", info.Checksum)
	}
	if info.ForceUpdate != false {
		t.Errorf("ゼロ値ForceUpdate = %v, want false", info.ForceUpdate)
	}
}

// TestUpdateInfo_UpToDateJSON は{"up_to_date": true}の解析挙動を確認する。
// Check()内のロジックをJSONデシリアライズの観点でテストする。
func TestUpdateInfo_UpToDateJSON(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantUpToDate bool
	}{
		{"up_to_date=true", `{"up_to_date":true}`, true},
		{"up_to_date=false", `{"up_to_date":false}`, false},
		{"フィールドなし", `{"version":"1.0.0","url":"/dl/agent"}`, false},
		{"空オブジェクト", `{}`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(tc.body), &raw); err != nil {
				t.Fatalf("Unmarshalエラー: %v", err)
			}
			upToDate, _ := raw["up_to_date"].(bool)
			if upToDate != tc.wantUpToDate {
				t.Errorf("up_to_date = %v, want %v", upToDate, tc.wantUpToDate)
			}
		})
	}
}
