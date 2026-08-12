package yara

import (
	"strings"
	"testing"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func textRule(id, name, value, condition string) *Rule {
	return &Rule{
		ID:        id,
		Name:      name,
		Strings:   []YaraString{{ID: "$s1", Type: "text", Value: value}},
		Condition: condition,
	}
}

// ─── NewEngine ────────────────────────────────────────────────────────────────

func TestNewEngine_NotNil(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine は nil を返すべきではありません")
	}
}

func TestNewEngine_InitialRuleCountZero(t *testing.T) {
	e := NewEngine()
	if e.RuleCount() != 0 {
		t.Errorf("NewEngine: RuleCount got %d, want 0", e.RuleCount())
	}
}

func TestNewEngine_InitialScansZero(t *testing.T) {
	e := NewEngine()
	if e.TotalScans() != 0 {
		t.Errorf("NewEngine: TotalScans got %d, want 0", e.TotalScans())
	}
}

// ─── LoadRule ─────────────────────────────────────────────────────────────────

func TestLoadRule_NilRule_ReturnsError(t *testing.T) {
	e := NewEngine()
	if err := e.LoadRule(nil); err == nil {
		t.Error("nil ルールはエラーを返すべきです")
	}
}

func TestLoadRule_EmptyID_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{Name: "No ID", Strings: []YaraString{{ID: "$s1", Type: "text", Value: "test"}}}
	if err := e.LoadRule(rule); err == nil {
		t.Error("空 ID はエラーを返すべきです")
	}
}

func TestLoadRule_EmptyName_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{ID: "rule1", Strings: []YaraString{{ID: "$s1", Type: "text", Value: "test"}}}
	if err := e.LoadRule(rule); err == nil {
		t.Error("空 Name はエラーを返すべきです")
	}
}

func TestLoadRule_InvalidCondition_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID: "bad-cond", Name: "Bad Condition",
		Strings:   []YaraString{{ID: "$s1", Type: "text", Value: "x"}},
		Condition: "maybe",
	}
	if err := e.LoadRule(rule); err == nil {
		t.Error("不正な condition はエラーを返すべきです")
	}
}

func TestLoadRule_ValidTextRule_IncrementsCount(t *testing.T) {
	e := NewEngine()
	rule := textRule("r1", "Rule One", "malware", "any")
	if err := e.LoadRule(rule); err != nil {
		t.Fatalf("LoadRule: 予期しないエラー: %v", err)
	}
	if e.RuleCount() != 1 {
		t.Errorf("RuleCount: got %d, want 1", e.RuleCount())
	}
}

func TestLoadRule_DuplicateID_ReplacesExisting(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "Original", "foo", "any"))
	_ = e.LoadRule(textRule("r1", "Replaced", "bar", "any"))
	if e.RuleCount() != 1 {
		t.Errorf("重複ID: RuleCount got %d, want 1", e.RuleCount())
	}
	rules := e.ListRules()
	if rules[0].Name != "Replaced" {
		t.Errorf("重複ID: Name got %q, want Replaced", rules[0].Name)
	}
}

func TestLoadRule_DefaultConditionIsAny(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:      "r1",
		Name:    "No Condition",
		Strings: []YaraString{{ID: "$s1", Type: "text", Value: "x"}},
	}
	_ = e.LoadRule(rule)
	rules := e.ListRules()
	if rules[0].Condition != "any" {
		t.Errorf("デフォルト condition: got %q, want any", rules[0].Condition)
	}
}

func TestLoadRule_InvalidHex_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:      "r1",
		Name:    "Bad Hex",
		Strings: []YaraString{{ID: "$h1", Type: "hex", Value: "GG"}},
	}
	if err := e.LoadRule(rule); err == nil {
		t.Error("不正 hex はエラーを返すべきです")
	}
}

func TestLoadRule_InvalidRegex_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:      "r1",
		Name:    "Bad Regex",
		Strings: []YaraString{{ID: "$r1", Type: "regex", Value: "[invalid"}},
	}
	if err := e.LoadRule(rule); err == nil {
		t.Error("不正 regex はエラーを返すべきです")
	}
}

func TestLoadRule_UnknownStringType_ReturnsError(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:      "r1",
		Name:    "Unknown Type",
		Strings: []YaraString{{ID: "$x1", Type: "binary", Value: "abc"}},
	}
	if err := e.LoadRule(rule); err == nil {
		t.Error("未知の String タイプはエラーを返すべきです")
	}
}

// ─── ScanBytes ────────────────────────────────────────────────────────────────

func TestScanBytes_NoRules_ReturnsEmpty(t *testing.T) {
	e := NewEngine()
	matches := e.ScanBytes([]byte("some data"))
	if len(matches) != 0 {
		t.Errorf("ルールなし: got %d matches, want 0", len(matches))
	}
}

func TestScanBytes_TextMatch_ReturnsMatch(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "Malware Rule", "malware", "any"))
	matches := e.ScanBytes([]byte("this file contains malware patterns"))
	if len(matches) != 1 {
		t.Fatalf("テキストマッチ: got %d matches, want 1", len(matches))
	}
	if matches[0].RuleID != "r1" {
		t.Errorf("マッチ RuleID: got %q, want r1", matches[0].RuleID)
	}
}

func TestScanBytes_TextNoMatch_ReturnsEmpty(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "Malware Rule", "malware", "any"))
	matches := e.ScanBytes([]byte("this file is clean"))
	if len(matches) != 0 {
		t.Errorf("テキスト不一致: got %d matches, want 0", len(matches))
	}
}

func TestScanBytes_HexMatch_ReturnsMatch(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r2",
		Name: "Hex Rule",
		Strings: []YaraString{
			{ID: "$h1", Type: "hex", Value: "DEADBEEF"},
		},
		Condition: "any",
	}
	_ = e.LoadRule(rule)
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	matches := e.ScanBytes(data)
	if len(matches) != 1 {
		t.Errorf("Hex マッチ: got %d matches, want 1", len(matches))
	}
}

func TestScanBytes_RegexMatch_ReturnsMatch(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r3",
		Name: "Regex Rule",
		Strings: []YaraString{
			{ID: "$r1", Type: "regex", Value: `cmd\.exe\s+-enc`},
		},
		Condition: "any",
	}
	_ = e.LoadRule(rule)
	data := []byte("powershell cmd.exe -enc SGVsbG8=")
	matches := e.ScanBytes(data)
	if len(matches) != 1 {
		t.Errorf("Regex マッチ: got %d matches, want 1", len(matches))
	}
}

func TestScanBytes_NocaseModifier(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r4",
		Name: "Nocase Rule",
		Strings: []YaraString{
			{ID: "$s1", Type: "text", Value: "MALWARE", Modifiers: []string{"nocase"}},
		},
		Condition: "any",
	}
	_ = e.LoadRule(rule)
	matches := e.ScanBytes([]byte("this file has malware embedded"))
	if len(matches) != 1 {
		t.Errorf("nocase マッチ: got %d matches, want 1", len(matches))
	}
}

func TestScanBytes_ConditionAll_RequiresAllStrings(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r5",
		Name: "All Rule",
		Strings: []YaraString{
			{ID: "$s1", Type: "text", Value: "foo"},
			{ID: "$s2", Type: "text", Value: "bar"},
		},
		Condition: "all",
	}
	_ = e.LoadRule(rule)

	// データに "foo" のみ → 不一致
	if len(e.ScanBytes([]byte("only foo here"))) != 0 {
		t.Error("condition=all: foo のみは不一致のはずです")
	}
	// データに "foo" と "bar" → 一致
	if len(e.ScanBytes([]byte("foo and bar"))) != 1 {
		t.Error("condition=all: foo と bar が両方あれば一致するはずです")
	}
}

func TestScanBytes_ConditionNone_MatchesWhenNoStringsFound(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r6",
		Name: "None Rule",
		Strings: []YaraString{
			{ID: "$s1", Type: "text", Value: "malware"},
		},
		Condition: "none",
	}
	_ = e.LoadRule(rule)

	// "malware" が含まれない → 一致
	if len(e.ScanBytes([]byte("clean data"))) != 1 {
		t.Error("condition=none: パターンなしは一致するはずです")
	}
	// "malware" が含まれる → 不一致
	if len(e.ScanBytes([]byte("contains malware"))) != 0 {
		t.Error("condition=none: パターンあり時は不一致のはずです")
	}
}

func TestScanBytes_IncrementsTotalScans(t *testing.T) {
	e := NewEngine()
	e.ScanBytes([]byte("data"))
	e.ScanBytes([]byte("data"))
	if e.TotalScans() != 2 {
		t.Errorf("TotalScans: got %d, want 2", e.TotalScans())
	}
}

func TestScanBytes_MatchIncrementsTotalMatches(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "R1", "hit", "any"))
	e.ScanBytes([]byte("hit"))
	if e.TotalMatches() != 1 {
		t.Errorf("TotalMatches: got %d, want 1", e.TotalMatches())
	}
}

// ─── ScanProcess ──────────────────────────────────────────────────────────────

func TestScanProcess_MatchesByProcessName(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:   "r1",
		Name: "Powershell Encoded",
		Strings: []YaraString{
			{ID: "$s1", Type: "text", Value: "powershell.exe"},
			{ID: "$s2", Type: "text", Value: "-enc"},
		},
		Condition: "all",
	}
	_ = e.LoadRule(rule)
	matches := e.ScanProcess(1234, "powershell.exe", "powershell.exe -enc SGVsbG8=")
	if len(matches) != 1 {
		t.Errorf("ScanProcess: got %d matches, want 1", len(matches))
	}
}

func TestScanProcess_CaseInsensitiveMatch(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "Cmd Rule", "cmd.exe", "any"))
	// ScanProcess は小文字に変換して照合する
	matches := e.ScanProcess(999, "CMD.EXE", "CMD.EXE /c whoami")
	if len(matches) != 1 {
		t.Errorf("ScanProcess 大文字小文字: got %d matches, want 1", len(matches))
	}
}

func TestScanProcess_NoMatch_ReturnsEmpty(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "Evil Rule", "evil.exe", "any"))
	matches := e.ScanProcess(1, "explorer.exe", "C:\\Windows\\explorer.exe")
	if len(matches) != 0 {
		t.Errorf("ScanProcess 不一致: got %d matches, want 0", len(matches))
	}
}

// ─── LoadRulesFromYAML ────────────────────────────────────────────────────────

func TestLoadRulesFromYAML_ValidYAML_LoadsRules(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: yaml-rule-1
    name: YAML Rule One
    strings:
      - id: $s1
        type: text
        value: malicious
    condition: any
    severity: 8
`)
	e := NewEngine()
	if err := e.LoadRulesFromYAML(yamlData); err != nil {
		t.Fatalf("LoadRulesFromYAML: 予期しないエラー: %v", err)
	}
	if e.RuleCount() != 1 {
		t.Errorf("LoadRulesFromYAML: RuleCount got %d, want 1", e.RuleCount())
	}
}

func TestLoadRulesFromYAML_MultipleRules(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: rule-a
    name: Rule A
    strings:
      - id: $s1
        type: text
        value: foo
    condition: any
  - id: rule-b
    name: Rule B
    strings:
      - id: $s1
        type: text
        value: bar
    condition: any
`)
	e := NewEngine()
	if err := e.LoadRulesFromYAML(yamlData); err != nil {
		t.Fatalf("LoadRulesFromYAML (複数): 予期しないエラー: %v", err)
	}
	if e.RuleCount() != 2 {
		t.Errorf("LoadRulesFromYAML (複数): RuleCount got %d, want 2", e.RuleCount())
	}
}

func TestLoadRulesFromYAML_InvalidYAML_ReturnsError(t *testing.T) {
	e := NewEngine()
	// タブ文字で始まる行は YAML では不正
	err := e.LoadRulesFromYAML([]byte("\trules:\n  - foo"))
	if err == nil {
		t.Error("不正 YAML はエラーを返すべきです")
	}
}

func TestLoadRulesFromYAML_InvalidRules_ReturnsPartialError(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: ""
    name: ""
    strings:
      - id: $s1
        type: text
        value: x
    condition: any
`)
	e := NewEngine()
	err := e.LoadRulesFromYAML(yamlData)
	if err == nil {
		t.Error("無効ルール (空ID) はエラーを返すべきです")
	}
}

// ─── RemoveRule ───────────────────────────────────────────────────────────────

func TestRemoveRule_ExistingRule_ReturnsTrueAndDecrementsCount(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "R1", "foo", "any"))
	if !e.RemoveRule("r1") {
		t.Error("RemoveRule: 存在するルールは true を返すべきです")
	}
	if e.RuleCount() != 0 {
		t.Errorf("RemoveRule: RuleCount got %d, want 0", e.RuleCount())
	}
}

func TestRemoveRule_UnknownRule_ReturnsFalse(t *testing.T) {
	e := NewEngine()
	if e.RemoveRule("nonexistent") {
		t.Error("RemoveRule: 存在しないルールは false を返すべきです")
	}
}

// ─── ListRules ────────────────────────────────────────────────────────────────

func TestListRules_ReturnsCopy(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRule(textRule("r1", "R1", "foo", "any"))
	_ = e.LoadRule(textRule("r2", "R2", "bar", "any"))
	rules := e.ListRules()
	if len(rules) != 2 {
		t.Errorf("ListRules: got %d rules, want 2", len(rules))
	}
}

// ─── Match fields ──────────────────────────────────────────────────────────────

func TestScanBytes_MatchHasCorrectFields(t *testing.T) {
	e := NewEngine()
	rule := &Rule{
		ID:        "detect-1",
		Name:      "Detect Evil",
		Tags:      []string{"malware", "ransomware"},
		Severity:  9,
		Strings:   []YaraString{{ID: "$s1", Type: "text", Value: "evil"}},
		Condition: "any",
	}
	_ = e.LoadRule(rule)
	matches := e.ScanBytes([]byte("evil payload"))
	if len(matches) != 1 {
		t.Fatalf("Match フィールド: got %d matches, want 1", len(matches))
	}
	m := matches[0]
	if m.RuleID != "detect-1" {
		t.Errorf("Match.RuleID: got %q, want detect-1", m.RuleID)
	}
	if m.RuleName != "Detect Evil" {
		t.Errorf("Match.RuleName: got %q, want Detect Evil", m.RuleName)
	}
	if m.Severity != 9 {
		t.Errorf("Match.Severity: got %d, want 9", m.Severity)
	}
	if len(m.MatchedStrings) == 0 {
		t.Error("Match.MatchedStrings が空です")
	}
	if !strings.Contains(m.MatchedStrings[0], "$s1") {
		t.Errorf("Match.MatchedStrings[0]: got %q, want contains $s1", m.MatchedStrings[0])
	}
	if m.Timestamp.IsZero() {
		t.Error("Match.Timestamp がゼロ値です")
	}
}
