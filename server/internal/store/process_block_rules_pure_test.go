package store

import (
	"strings"
	"testing"
)

// ─── ProcessBlockRule 構造体フィールドテスト ──────────────────────────────────

// TestProcessBlockRule_DefaultEnabledIsFalse は ProcessBlockRule のゼロ値で Enabled が false であることを確認する
func TestProcessBlockRule_DefaultEnabledIsFalse(t *testing.T) {
	var r ProcessBlockRule
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestProcessBlockRule_DefaultScopeIDIsNil は ProcessBlockRule のゼロ値で ScopeID が nil であることを確認する
func TestProcessBlockRule_DefaultScopeIDIsNil(t *testing.T) {
	var r ProcessBlockRule
	if r.ScopeID != nil {
		t.Errorf("ScopeID のデフォルトは nil であるべき: got %v", r.ScopeID)
	}
}

// TestProcessBlockRule_ScopeIDCanBeSet は ScopeID に文字列ポインタを設定できることを確認する
func TestProcessBlockRule_ScopeIDCanBeSet(t *testing.T) {
	id := "agent-scope-uuid"
	r := ProcessBlockRule{ScopeID: &id}
	if r.ScopeID == nil {
		t.Fatal("ScopeID に値を設定後は nil でないべき")
	}
	if *r.ScopeID != id {
		t.Errorf("*ScopeID = %q, want %q", *r.ScopeID, id)
	}
}

// TestProcessBlockRule_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestProcessBlockRule_AllFieldsCanBeSet(t *testing.T) {
	scopeID := "agent-uuid-999"
	r := ProcessBlockRule{
		ID:          "rule-001",
		Name:        "Block cmd.exe",
		ProcessName: "cmd.exe",
		RuleType:    "deny",
		Scope:       "agent",
		ScopeID:     &scopeID,
		Action:      "block",
		Enabled:     true,
		Severity:    "high",
		CreatedAt:   "2026-03-23T00:00:00Z",
	}
	if r.ID != "rule-001" {
		t.Errorf("ID = %q, want 'rule-001'", r.ID)
	}
	if r.ProcessName != "cmd.exe" {
		t.Errorf("ProcessName = %q, want 'cmd.exe'", r.ProcessName)
	}
	if r.RuleType != "deny" {
		t.Errorf("RuleType = %q, want 'deny'", r.RuleType)
	}
	if r.Scope != "agent" {
		t.Errorf("Scope = %q, want 'agent'", r.Scope)
	}
	if !r.Enabled {
		t.Error("Enabled は true であるべき")
	}
}

// ─── ルールタイプ検証テスト ────────────────────────────────────────────────────

// isValidProcessBlockRuleType はプロセスブロックルールタイプが有効かどうかを検証する純粋関数
func isValidProcessBlockRuleType(ruleType string) bool {
	switch ruleType {
	case "deny", "allow", "monitor":
		return true
	}
	return false
}

// TestIsValidProcessBlockRuleType_KnownTypesAreValid は既知のルールタイプが有効であることを確認する
func TestIsValidProcessBlockRuleType_KnownTypesAreValid(t *testing.T) {
	validTypes := []string{"deny", "allow", "monitor"}
	for _, rt := range validTypes {
		if !isValidProcessBlockRuleType(rt) {
			t.Errorf("ルールタイプ %q は有効であるべき", rt)
		}
	}
}

// TestIsValidProcessBlockRuleType_UnknownTypesAreInvalid は不明なルールタイプが無効であることを確認する
func TestIsValidProcessBlockRuleType_UnknownTypesAreInvalid(t *testing.T) {
	invalidTypes := []string{"block", "reject", "", "DENY", "Allow"}
	for _, rt := range invalidTypes {
		if isValidProcessBlockRuleType(rt) {
			t.Errorf("ルールタイプ %q は無効であるべき", rt)
		}
	}
}

// ─── スコープ検証テスト ────────────────────────────────────────────────────────

// isValidProcessBlockScope はスコープ値が有効かどうかを検証する純粋関数
func isValidProcessBlockScope(scope string) bool {
	switch scope {
	case "all", "agent", "group":
		return true
	}
	return false
}

// TestIsValidProcessBlockScope_KnownScopesAreValid は既知のスコープが有効であることを確認する
func TestIsValidProcessBlockScope_KnownScopesAreValid(t *testing.T) {
	validScopes := []string{"all", "agent", "group"}
	for _, s := range validScopes {
		if !isValidProcessBlockScope(s) {
			t.Errorf("スコープ %q は有効であるべき", s)
		}
	}
}

// TestIsValidProcessBlockScope_UnknownScopesAreInvalid は不明なスコープが無効であることを確認する
func TestIsValidProcessBlockScope_UnknownScopesAreInvalid(t *testing.T) {
	invalidScopes := []string{"tenant", "global", "", "ALL", "Agent"}
	for _, s := range invalidScopes {
		if isValidProcessBlockScope(s) {
			t.Errorf("スコープ %q は無効であるべき", s)
		}
	}
}

// TestIsValidProcessBlockScope_CaseSensitive はスコープ判定が大文字小文字を区別することを確認する
func TestIsValidProcessBlockScope_CaseSensitive(t *testing.T) {
	if isValidProcessBlockScope("ALL") {
		t.Error("スコープ判定は大文字小文字を区別するべき ('ALL' は無効)")
	}
	if isValidProcessBlockScope("Agent") {
		t.Error("スコープ判定は大文字小文字を区別するべき ('Agent' は無効)")
	}
}

// ─── アクション検証テスト ──────────────────────────────────────────────────────

// isValidProcessBlockAction はアクション値が有効かどうかを検証する純粋関数
func isValidProcessBlockAction(action string) bool {
	switch action {
	case "block", "alert", "log":
		return true
	}
	return false
}

// TestIsValidProcessBlockAction_KnownActionsAreValid は既知のアクションが有効であることを確認する
func TestIsValidProcessBlockAction_KnownActionsAreValid(t *testing.T) {
	validActions := []string{"block", "alert", "log"}
	for _, a := range validActions {
		if !isValidProcessBlockAction(a) {
			t.Errorf("アクション %q は有効であるべき", a)
		}
	}
}

// TestIsValidProcessBlockAction_UnknownActionsAreInvalid は不明なアクションが無効であることを確認する
func TestIsValidProcessBlockAction_UnknownActionsAreInvalid(t *testing.T) {
	invalidActions := []string{"kill", "quarantine", "", "BLOCK", "Alert"}
	for _, a := range invalidActions {
		if isValidProcessBlockAction(a) {
			t.Errorf("アクション %q は無効であるべき", a)
		}
	}
}

// ─── プロセス名パスヘルパーテスト ─────────────────────────────────────────────

// processNameIsWindowsExecutable はプロセス名が .exe で終わるかどうかを確認する純粋関数
func processNameIsWindowsExecutable(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".exe")
}

// TestProcessNameIsWindowsExecutable_EXESuffix は .exe サフィックスが検出されることを確認する
func TestProcessNameIsWindowsExecutable_EXESuffix(t *testing.T) {
	exeNames := []string{"cmd.exe", "powershell.exe", "notepad.exe", "malware.EXE", "Tool.Exe"}
	for _, name := range exeNames {
		if !processNameIsWindowsExecutable(name) {
			t.Errorf("プロセス名 %q は .exe 形式として認識されるべき", name)
		}
	}
}

// TestProcessNameIsWindowsExecutable_NonEXEIsNotWindowsExe は非 .exe プロセスが .exe と判定されないことを確認する
func TestProcessNameIsWindowsExecutable_NonEXEIsNotWindowsExe(t *testing.T) {
	nonExeNames := []string{"bash", "python3", "nginx", "chrome", "script.sh", ""}
	for _, name := range nonExeNames {
		if processNameIsWindowsExecutable(name) {
			t.Errorf("プロセス名 %q は .exe として判定されるべきでない", name)
		}
	}
}

// processNameHasPathSeparator はプロセス名にパス区切り文字が含まれるかを確認する純粋関数
func processNameHasPathSeparator(name string) bool {
	return strings.Contains(name, "/") || strings.Contains(name, "\\")
}

// TestProcessNameHasPathSeparator_UnixPaths はUnixパスが検出されることを確認する
func TestProcessNameHasPathSeparator_UnixPaths(t *testing.T) {
	paths := []string{"/usr/bin/bash", "/bin/sh", "/opt/app/server"}
	for _, p := range paths {
		if !processNameHasPathSeparator(p) {
			t.Errorf("Unixパス %q はパス区切り文字を含むと認識されるべき", p)
		}
	}
}

// TestProcessNameHasPathSeparator_WindowsPaths はWindowsパスが検出されることを確認する
func TestProcessNameHasPathSeparator_WindowsPaths(t *testing.T) {
	paths := []string{`C:\Windows\System32\cmd.exe`, `C:\Program Files\app.exe`}
	for _, p := range paths {
		if !processNameHasPathSeparator(p) {
			t.Errorf("Windowsパス %q はパス区切り文字を含むと認識されるべき", p)
		}
	}
}

// TestProcessNameHasPathSeparator_PlainNameHasNoSeparator は単純なプロセス名にパス区切り文字がないことを確認する
func TestProcessNameHasPathSeparator_PlainNameHasNoSeparator(t *testing.T) {
	plainNames := []string{"cmd.exe", "bash", "nginx", "python3"}
	for _, name := range plainNames {
		if processNameHasPathSeparator(name) {
			t.Errorf("単純なプロセス名 %q はパス区切り文字を含まないべき", name)
		}
	}
}

// ─── ProcessBlockRuleFilter 構造体テスト ──────────────────────────────────────

// TestProcessBlockRuleFilter_DefaultLimitIsZero は ProcessBlockRuleFilter のデフォルト Limit がゼロであることを確認する
func TestProcessBlockRuleFilter_DefaultLimitIsZero(t *testing.T) {
	var f ProcessBlockRuleFilter
	if f.Limit != 0 {
		t.Errorf("ProcessBlockRuleFilter.Limit のデフォルト = %d, want 0", f.Limit)
	}
}

// TestProcessBlockRuleFilter_EnabledPointerCanBeSet は Enabled ポインタを設定できることを確認する
func TestProcessBlockRuleFilter_EnabledPointerCanBeSet(t *testing.T) {
	trueVal := true
	f := ProcessBlockRuleFilter{Enabled: &trueVal}
	if f.Enabled == nil {
		t.Fatal("Enabled に true を設定後は nil でないべき")
	}
	if !*f.Enabled {
		t.Error("*Enabled = false, want true")
	}
}

// TestProcessBlockRuleFilter_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestProcessBlockRuleFilter_AllFieldsCanBeSet(t *testing.T) {
	enabled := false
	f := ProcessBlockRuleFilter{
		RuleType: "deny",
		Scope:    "all",
		Enabled:  &enabled,
		Limit:    50,
		Offset:   100,
	}
	if f.RuleType != "deny" {
		t.Errorf("RuleType = %q, want 'deny'", f.RuleType)
	}
	if f.Scope != "all" {
		t.Errorf("Scope = %q, want 'all'", f.Scope)
	}
	if f.Limit != 50 {
		t.Errorf("Limit = %d, want 50", f.Limit)
	}
	if f.Offset != 100 {
		t.Errorf("Offset = %d, want 100", f.Offset)
	}
}

// ─── CreateProcessBlockRuleInput デフォルト値テスト ───────────────────────────

// TestCreateProcessBlockRuleInput_ZeroValueHasEmptyDefaults は CreateProcessBlockRuleInput のゼロ値が空文字列を持つことを確認する
// Create() は RuleType/Scope/Action/Severity が空の場合にデフォルト値を設定するが、
// 入力構造体自体のゼロ値は空文字列であるべき
func TestCreateProcessBlockRuleInput_ZeroValueHasEmptyDefaults(t *testing.T) {
	var in CreateProcessBlockRuleInput
	if in.RuleType != "" {
		t.Errorf("RuleType のデフォルトは空文字列: got %q", in.RuleType)
	}
	if in.Scope != "" {
		t.Errorf("Scope のデフォルトは空文字列: got %q", in.Scope)
	}
	if in.Action != "" {
		t.Errorf("Action のデフォルトは空文字列: got %q", in.Action)
	}
	if in.Severity != "" {
		t.Errorf("Severity のデフォルトは空文字列: got %q", in.Severity)
	}
	if in.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if in.ScopeID != nil {
		t.Errorf("ScopeID のデフォルトは nil であるべき: got %v", in.ScopeID)
	}
}

// TestCreateProcessBlockRuleInput_AllFieldsAssignable は全フィールドを代入できることを確認する
func TestCreateProcessBlockRuleInput_AllFieldsAssignable(t *testing.T) {
	scopeID := "scope-uuid"
	in := CreateProcessBlockRuleInput{
		Name:        "Block PowerShell",
		ProcessName: "powershell.exe",
		RuleType:    "deny",
		Scope:       "all",
		ScopeID:     &scopeID,
		Action:      "block",
		Enabled:     true,
		Severity:    "critical",
	}
	if in.Name != "Block PowerShell" {
		t.Errorf("Name = %q, want 'Block PowerShell'", in.Name)
	}
	if in.ProcessName != "powershell.exe" {
		t.Errorf("ProcessName = %q, want 'powershell.exe'", in.ProcessName)
	}
	if in.ScopeID == nil || *in.ScopeID != scopeID {
		t.Errorf("ScopeID = %v, want %q", in.ScopeID, scopeID)
	}
	if in.Severity != "critical" {
		t.Errorf("Severity = %q, want 'critical'", in.Severity)
	}
}
