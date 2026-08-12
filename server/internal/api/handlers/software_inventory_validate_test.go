package handlers

import (
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// normalizeSoftwareName のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeSoftwareName_LowercaseConversion(t *testing.T) {
	// 大文字を小文字に変換する
	tests := []struct {
		input string
		want  string
	}{
		{"Microsoft Office", "microsoft office"},
		{"OPENSSL", "openssl"},
		{"Node.JS", "node.js"},
		{"Log4J", "log4j"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeSoftwareName(tc.input)
			if got != tc.want {
				t.Errorf("normalizeSoftwareName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeSoftwareName_TrimSpaces(t *testing.T) {
	// 前後の空白を除去する
	got := normalizeSoftwareName("  curl  ")
	want := "curl"
	if got != want {
		t.Errorf("normalizeSoftwareName(\"  curl  \") = %q, want %q", got, want)
	}
}

func TestNormalizeSoftwareName_EmptyString(t *testing.T) {
	// 空文字列はそのまま空文字列を返す
	got := normalizeSoftwareName("")
	if got != "" {
		t.Errorf("normalizeSoftwareName(\"\") = %q, want \"\"", got)
	}
}

func TestNormalizeSoftwareName_AlreadyNormalized(t *testing.T) {
	// すでに正規化済みの文字列はそのまま返す
	input := "python3.11"
	got := normalizeSoftwareName(input)
	if got != input {
		t.Errorf("normalizeSoftwareName(%q) = %q, want %q", input, got, input)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateSoftwareEntry のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateSoftwareEntry_Valid(t *testing.T) {
	// 有効なエントリはエラーなく通過する
	tests := []struct {
		name    string
		version string
	}{
		{"curl", "7.88.0"},
		{"OpenSSL", "3.0.8"},
		{"Microsoft Office", "16.0"},
		{"a", ""},
		{"SomeSoftware", strings.Repeat("v", 100)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSoftwareEntry(tc.name, tc.version)
			if got != "" {
				t.Errorf("validateSoftwareEntry(%q, %q) = %q, want \"\"", tc.name, tc.version, got)
			}
		})
	}
}

func TestValidateSoftwareEntry_EmptyNameIsInvalid(t *testing.T) {
	// name が空の場合はエラーを返す
	got := validateSoftwareEntry("", "1.0")
	if got == "" {
		t.Error("validateSoftwareEntry(\"\", \"1.0\") = \"\", エラーが期待されました")
	}
}

func TestValidateSoftwareEntry_SpaceOnlyNameIsInvalid(t *testing.T) {
	// name がスペースのみの場合もエラーを返す
	got := validateSoftwareEntry("   ", "1.0")
	if got == "" {
		t.Error("validateSoftwareEntry(\"   \", \"1.0\") = \"\", エラーが期待されました")
	}
}

func TestValidateSoftwareEntry_NameTooLong(t *testing.T) {
	// 255 文字を超える name はエラーを返す
	longName := strings.Repeat("a", 256)
	got := validateSoftwareEntry(longName, "1.0")
	if got == "" {
		t.Error("validateSoftwareEntry(256文字名前) = \"\", エラーが期待されました")
	}
}

func TestValidateSoftwareEntry_VersionTooLong(t *testing.T) {
	// 100 文字を超える version はエラーを返す
	longVersion := strings.Repeat("1", 101)
	got := validateSoftwareEntry("curl", longVersion)
	if got == "" {
		t.Error("validateSoftwareEntry(バージョン101文字) = \"\", エラーが期待されました")
	}
}

func TestValidateSoftwareEntry_VersionEmptyIsValid(t *testing.T) {
	// version は空でも有効
	got := validateSoftwareEntry("curl", "")
	if got != "" {
		t.Errorf("validateSoftwareEntry(\"curl\", \"\") = %q, want \"\"", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isSoftwareVulnerable のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestIsSoftwareVulnerable_KnownVulnerable(t *testing.T) {
	// 既知の脆弱なキーワードを含むソフトウェア名は true を返す
	vulnerable := []string{
		"log4j-core",
		"OpenSSL 1.0.2",
		"curl 7.29.0",
		"libssl1.1",
		"Apache HTTPD",
		"nginx 1.18",
		"Python 2.7",
		"Java Runtime Environment",
	}
	for _, name := range vulnerable {
		t.Run(name, func(t *testing.T) {
			if !isSoftwareVulnerable(name) {
				t.Errorf("isSoftwareVulnerable(%q) = false, want true", name)
			}
		})
	}
}

func TestIsSoftwareVulnerable_NotVulnerable(t *testing.T) {
	// 脆弱なキーワードを含まないソフトウェア名は false を返す
	safe := []string{
		"Microsoft Word",
		"Google Chrome",
		"Zoom Client",
		"Slack Desktop",
		"7-Zip",
	}
	for _, name := range safe {
		t.Run(name, func(t *testing.T) {
			if isSoftwareVulnerable(name) {
				t.Errorf("isSoftwareVulnerable(%q) = true, want false", name)
			}
		})
	}
}

func TestIsSoftwareVulnerable_CaseInsensitive(t *testing.T) {
	// 大文字小文字を区別しない
	tests := []struct {
		input string
	}{
		{"LOG4J"},
		{"Log4J"},
		{"OPENSSL"},
		{"OpenSSL"},
		{"CURL"},
		{"Curl"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if !isSoftwareVulnerable(tc.input) {
				t.Errorf("isSoftwareVulnerable(%q) = false, 大文字小文字を無視して true が期待されました", tc.input)
			}
		})
	}
}

func TestIsSoftwareVulnerable_EmptyString(t *testing.T) {
	// 空文字列は false を返す
	if isSoftwareVulnerable("") {
		t.Error("isSoftwareVulnerable(\"\") = true, want false")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// filterVulnerableSoftware のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestFilterVulnerableSoftware_FiltersCorrectly(t *testing.T) {
	// 脆弱なソフトウェアのみを返す
	entries := []*store.SoftwareEntry{
		{Name: "Microsoft Word", AgentID: "a1"},
		{Name: "log4j-core", AgentID: "a1"},
		{Name: "Google Chrome", AgentID: "a1"},
		{Name: "OpenSSL", AgentID: "a1"},
		{Name: "Slack", AgentID: "a1"},
	}
	got := filterVulnerableSoftware(entries)
	if len(got) != 2 {
		t.Errorf("filterVulnerableSoftware: %d 件返しました、2 件が期待されます; got %v",
			len(got), namesOf(got))
	}
}

func TestFilterVulnerableSoftware_EmptyInput(t *testing.T) {
	// 空のリストは空のリストを返す
	got := filterVulnerableSoftware([]*store.SoftwareEntry{})
	if len(got) != 0 {
		t.Errorf("filterVulnerableSoftware([]): len = %d, want 0", len(got))
	}
}

func TestFilterVulnerableSoftware_NoneVulnerable(t *testing.T) {
	// 脆弱なソフトウェアがない場合は nil または空スライスを返す
	entries := []*store.SoftwareEntry{
		{Name: "Microsoft Word"},
		{Name: "Zoom Client"},
	}
	got := filterVulnerableSoftware(entries)
	if len(got) != 0 {
		t.Errorf("filterVulnerableSoftware(安全なソフトウェアのみ): len = %d, want 0", len(got))
	}
}

func TestFilterVulnerableSoftware_AllVulnerable(t *testing.T) {
	// すべてが脆弱な場合は全件返す
	entries := []*store.SoftwareEntry{
		{Name: "log4j"},
		{Name: "openssl"},
		{Name: "curl"},
	}
	got := filterVulnerableSoftware(entries)
	if len(got) != 3 {
		t.Errorf("filterVulnerableSoftware(全件脆弱): len = %d, want 3", len(got))
	}
}

// namesOf は SoftwareEntry スライスから名前のリストを返すテストヘルパーです。
func namesOf(entries []*store.SoftwareEntry) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	return names
}
