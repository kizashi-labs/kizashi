package sync

import (
	"testing"
)

// ─── NewSigmaHQSyncer ─────────────────────────────────────────────────────────

func TestNewSigmaHQSyncer_NotNil(t *testing.T) {
	s := NewSigmaHQSyncer(nil, "")
	if s == nil {
		t.Fatal("NewSigmaHQSyncer は nil を返すべきではありません")
	}
}

func TestNewSigmaHQSyncer_HTTPClientNotNil(t *testing.T) {
	s := NewSigmaHQSyncer(nil, "")
	if s.client == nil {
		t.Error("httpClient が nil です")
	}
}

func TestNewSigmaHQSyncer_GithubTokenStored(t *testing.T) {
	s := NewSigmaHQSyncer(nil, "my-token")
	if s.githubToken != "my-token" {
		t.Errorf("githubToken: got %q, want my-token", s.githubToken)
	}
}

// ─── Status / IsRunning ───────────────────────────────────────────────────────

func TestStatus_Initially_ReturnsNil(t *testing.T) {
	s := NewSigmaHQSyncer(nil, "")
	if s.Status() != nil {
		t.Error("初期状態: Status() は nil を返すべきです")
	}
}

func TestIsRunning_Initially_ReturnsFalse(t *testing.T) {
	s := NewSigmaHQSyncer(nil, "")
	if s.IsRunning() {
		t.Error("初期状態: IsRunning() は false を返すべきです")
	}
}

// ─── levelToSeverity ─────────────────────────────────────────────────────────

func TestLevelToSeverity_Informational_Returns1(t *testing.T) {
	if got := levelToSeverity("informational"); got != 1 {
		t.Errorf("informational: got %d, want 1", got)
	}
}

func TestLevelToSeverity_Low_Returns3(t *testing.T) {
	if got := levelToSeverity("low"); got != 3 {
		t.Errorf("low: got %d, want 3", got)
	}
}

func TestLevelToSeverity_Medium_Returns5(t *testing.T) {
	if got := levelToSeverity("medium"); got != 5 {
		t.Errorf("medium: got %d, want 5", got)
	}
}

func TestLevelToSeverity_High_Returns7(t *testing.T) {
	if got := levelToSeverity("high"); got != 7 {
		t.Errorf("high: got %d, want 7", got)
	}
}

func TestLevelToSeverity_Critical_Returns9(t *testing.T) {
	if got := levelToSeverity("critical"); got != 9 {
		t.Errorf("critical: got %d, want 9", got)
	}
}

func TestLevelToSeverity_Unknown_Returns5(t *testing.T) {
	if got := levelToSeverity("unknown_level"); got != 5 {
		t.Errorf("unknown: got %d, want 5", got)
	}
}

func TestLevelToSeverity_CaseInsensitive(t *testing.T) {
	if got := levelToSeverity("CRITICAL"); got != 9 {
		t.Errorf("CRITICAL (大文字): got %d, want 9", got)
	}
}

// ─── inferPlatforms ───────────────────────────────────────────────────────────

func TestInferPlatforms_Windows_ReturnsWindows(t *testing.T) {
	p := inferPlatforms("windows", "rules/windows/rule.yml")
	if len(p) != 1 || p[0] != "windows" {
		t.Errorf("windows product: got %v, want [windows]", p)
	}
}

func TestInferPlatforms_Linux_ReturnsLinux(t *testing.T) {
	p := inferPlatforms("linux", "rules/linux/rule.yml")
	if len(p) != 1 || p[0] != "linux" {
		t.Errorf("linux product: got %v, want [linux]", p)
	}
}

func TestInferPlatforms_MacOS_ReturnsMacOS(t *testing.T) {
	p := inferPlatforms("macos", "rules/macos/rule.yml")
	if len(p) != 1 || p[0] != "macos" {
		t.Errorf("macos product: got %v, want [macos]", p)
	}
}

func TestInferPlatforms_Darwin_ReturnsMacOS(t *testing.T) {
	p := inferPlatforms("darwin", "")
	if len(p) != 1 || p[0] != "macos" {
		t.Errorf("darwin product: got %v, want [macos]", p)
	}
}

func TestInferPlatforms_Unknown_ReturnsAll(t *testing.T) {
	p := inferPlatforms("unknown", "rules/generic/rule.yml")
	if len(p) != 3 {
		t.Errorf("unknown product: got %v, want 3 platforms", p)
	}
}

func TestInferPlatforms_WindowsInPath_ReturnsWindows(t *testing.T) {
	p := inferPlatforms("", "rules/windows/process_creation.yml")
	if len(p) != 1 || p[0] != "windows" {
		t.Errorf("windows path: got %v, want [windows]", p)
	}
}

// ─── parseSigmaYAML ───────────────────────────────────────────────────────────

func TestParseSigmaYAML_Valid_ReturnsRule(t *testing.T) {
	content := []byte(`
id: 12345678-1234-1234-1234-123456789012
title: Test Rule
description: A test rule
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  keywords:
    - suspicious
  condition: keywords
`)
	rule, err := parseSigmaYAML(content, "rules/windows/test.yml", false)
	if err != nil {
		t.Fatalf("parseSigmaYAML: 予期しないエラー: %v", err)
	}
	if rule == nil {
		t.Fatal("parseSigmaYAML: nil が返されました")
	}
	if rule.Name != "Test Rule" {
		t.Errorf("Name: got %q, want Test Rule", rule.Name)
	}
	if rule.Severity != 7 {
		t.Errorf("Severity (high→7): got %d, want 7", rule.Severity)
	}
	if rule.Source != "sigmahq" {
		t.Errorf("Source: got %q, want sigmahq", rule.Source)
	}
}

func TestParseSigmaYAML_MissingID_ReturnsError(t *testing.T) {
	content := []byte(`
title: Test Rule
status: stable
level: medium
`)
	_, err := parseSigmaYAML(content, "", false)
	if err == nil {
		t.Error("ID なし: エラーを返すべきです")
	}
}

func TestParseSigmaYAML_MissingTitle_ReturnsError(t *testing.T) {
	content := []byte(`
id: 12345678-1234-1234-1234-123456789012
status: stable
level: medium
`)
	_, err := parseSigmaYAML(content, "", false)
	if err == nil {
		t.Error("Title なし: エラーを返すべきです")
	}
}

func TestParseSigmaYAML_DeprecatedStatus_ReturnsError(t *testing.T) {
	content := []byte(`
id: 12345678-1234-1234-1234-123456789012
title: Deprecated Rule
status: deprecated
level: low
`)
	_, err := parseSigmaYAML(content, "", false)
	if err == nil {
		t.Error("deprecated ルール: エラーを返すべきです")
	}
}

func TestParseSigmaYAML_AutoEnable_StableEnabled(t *testing.T) {
	content := []byte(`
id: 12345678-1234-1234-1234-123456789012
title: Stable Rule
status: stable
level: medium
`)
	rule, err := parseSigmaYAML(content, "", true)
	if err != nil {
		t.Fatalf("parseSigmaYAML: %v", err)
	}
	if !rule.Enabled {
		t.Error("autoEnable=true, status=stable: Enabled should be true")
	}
}

func TestParseSigmaYAML_MITRETags_Extracted(t *testing.T) {
	content := []byte(`
id: 12345678-1234-1234-1234-123456789012
title: MITRE Rule
status: stable
level: high
tags:
  - attack.t1059.001
  - attack.lateral_movement
`)
	rule, _ := parseSigmaYAML(content, "", false)
	if len(rule.MITRETags) != 1 {
		t.Errorf("MITRETags: got %d, want 1 (T-prefix tags only)", len(rule.MITRETags))
	}
	if rule.MITRETags[0] != "T1059.001" {
		t.Errorf("MITRETags[0]: got %q, want T1059.001", rule.MITRETags[0])
	}
}

// ─── mapWazuhStatus ───────────────────────────────────────────────────────────

func TestMapWazuhStatus_Active_ReturnsOnline(t *testing.T) {
	if got := mapWazuhStatus("active"); got != "online" {
		t.Errorf("active: got %q, want online", got)
	}
}

func TestMapWazuhStatus_Disconnected_ReturnsOffline(t *testing.T) {
	if got := mapWazuhStatus("disconnected"); got != "offline" {
		t.Errorf("disconnected: got %q, want offline", got)
	}
}

func TestMapWazuhStatus_Unknown_ReturnsOffline(t *testing.T) {
	if got := mapWazuhStatus("unknown"); got != "offline" {
		t.Errorf("unknown: got %q, want offline", got)
	}
}
