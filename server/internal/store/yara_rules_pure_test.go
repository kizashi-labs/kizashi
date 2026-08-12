package store

import (
	"strings"
	"testing"
)

// ─── YARARule 構造体フィールドテスト ──────────────────────────────────────────

// TestYARARule_DefaultTagsIsNil は YARARule のゼロ値で Tags が nil であることを確認する
func TestYARARule_DefaultTagsIsNil(t *testing.T) {
	var r YARARule
	if r.Tags != nil {
		t.Errorf("Tags のデフォルトは nil であるべき: got %v", r.Tags)
	}
}

// TestYARARule_DefaultEnabledIsFalse は YARARule のゼロ値で Enabled が false であることを確認する
func TestYARARule_DefaultEnabledIsFalse(t *testing.T) {
	var r YARARule
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestYARARule_SeverityFieldAssignment は既知の severity 値を設定できることを確認する
func TestYARARule_SeverityFieldAssignment(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		r := YARARule{Severity: sev}
		if r.Severity != sev {
			t.Errorf("Severity = %q, want %q", r.Severity, sev)
		}
	}
}

// TestYARARule_TagsCanBeSetToEmptySlice は Tags を空スライスに設定できることを確認する
func TestYARARule_TagsCanBeSetToEmptySlice(t *testing.T) {
	r := YARARule{Tags: []string{}}
	if r.Tags == nil {
		t.Error("Tags は nil でなく空スライスであるべき")
	}
	if len(r.Tags) != 0 {
		t.Errorf("Tags の長さ = %d, want 0", len(r.Tags))
	}
}

// TestYARARule_TagsCanContainMultipleValues は Tags に複数の値を設定できることを確認する
func TestYARARule_TagsCanContainMultipleValues(t *testing.T) {
	tags := []string{"malware", "ransomware", "apt", "windows"}
	r := YARARule{Tags: tags}
	if len(r.Tags) != 4 {
		t.Errorf("タグ数 = %d, want 4", len(r.Tags))
	}
	for i, tag := range tags {
		if r.Tags[i] != tag {
			t.Errorf("Tags[%d] = %q, want %q", i, r.Tags[i], tag)
		}
	}
}

// TestYARARule_CreatedByIsNilByDefault は CreatedBy ポインタがデフォルトで nil であることを確認する
func TestYARARule_CreatedByIsNilByDefault(t *testing.T) {
	var r YARARule
	if r.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき: got %v", r.CreatedBy)
	}
}

// TestYARARule_LastMatchedAtIsNilByDefault は LastMatchedAt ポインタがデフォルトで nil であることを確認する
func TestYARARule_LastMatchedAtIsNilByDefault(t *testing.T) {
	var r YARARule
	if r.LastMatchedAt != nil {
		t.Errorf("LastMatchedAt のデフォルトは nil であるべき: got %v", r.LastMatchedAt)
	}
}

// TestYARARule_LastMatchedAtCanBeSet は LastMatchedAt に文字列ポインタを設定できることを確認する
func TestYARARule_LastMatchedAtCanBeSet(t *testing.T) {
	ts := "2026-03-23T10:00:00Z"
	r := YARARule{LastMatchedAt: &ts}
	if r.LastMatchedAt == nil {
		t.Fatal("LastMatchedAt に値を設定後は nil でないべき")
	}
	if *r.LastMatchedAt != ts {
		t.Errorf("*LastMatchedAt = %q, want %q", *r.LastMatchedAt, ts)
	}
}

// ─── YARA ルール名前・コンテンツ検証テスト ────────────────────────────────────

// yaraNameIsValid は YARA ルール名が有効かどうかを検証する純粋関数
// 空文字列と空白のみは無効、非空は有効とする
func yaraNameIsValid(name string) bool {
	return strings.TrimSpace(name) != ""
}

// TestYARANameIsValid_EmptyNameIsInvalid は空のルール名が無効であることを確認する
func TestYARANameIsValid_EmptyNameIsInvalid(t *testing.T) {
	if yaraNameIsValid("") {
		t.Error("空のルール名は無効であるべき")
	}
}

// TestYARANameIsValid_WhitespaceOnlyIsInvalid は空白のみのルール名が無効であることを確認する
func TestYARANameIsValid_WhitespaceOnlyIsInvalid(t *testing.T) {
	whitespaceNames := []string{" ", "  ", "\t", "\n"}
	for _, name := range whitespaceNames {
		if yaraNameIsValid(name) {
			t.Errorf("空白のみのルール名 %q は無効であるべき", name)
		}
	}
}

// TestYARANameIsValid_NonEmptyNameIsValid は非空ルール名が有効であることを確認する
func TestYARANameIsValid_NonEmptyNameIsValid(t *testing.T) {
	validNames := []string{
		"detect_ransomware",
		"APT_Backdoor_v2",
		"suspicious_powershell",
		"malware.generic",
	}
	for _, name := range validNames {
		if !yaraNameIsValid(name) {
			t.Errorf("ルール名 %q は有効であるべき", name)
		}
	}
}

// ─── YARA ルールコンテンツ構造テスト ──────────────────────────────────────────

// yaraContentHasRuleKeyword は YARA コンテンツに "rule" キーワードが含まれるかを確認する純粋関数
func yaraContentHasRuleKeyword(content string) bool {
	return strings.Contains(content, "rule ")
}

// TestYARAContentHasRuleKeyword_ValidContent は rule キーワードを含むコンテンツが合格することを確認する
func TestYARAContentHasRuleKeyword_ValidContent(t *testing.T) {
	content := `rule detect_malware {
    strings:
        $a = "malware_string"
    condition:
        $a
}`
	if !yaraContentHasRuleKeyword(content) {
		t.Error("YARA コンテンツに 'rule' キーワードが含まれるべき")
	}
}

// TestYARAContentHasRuleKeyword_EmptyContentFails は空のコンテンツが rule キーワードを持たないことを確認する
func TestYARAContentHasRuleKeyword_EmptyContentFails(t *testing.T) {
	if yaraContentHasRuleKeyword("") {
		t.Error("空のコンテンツは 'rule' キーワードを持たないべき")
	}
}

// TestYARAContentHasRuleKeyword_ContentWithoutRuleFails は rule キーワードなしのコンテンツが拒否されることを確認する
func TestYARAContentHasRuleKeyword_ContentWithoutRuleFails(t *testing.T) {
	noRuleContent := "strings: $a = \"test\""
	if yaraContentHasRuleKeyword(noRuleContent) {
		t.Error("'rule' キーワードがないコンテンツは false を返すべき")
	}
}

// ─── YARAListFilter 構造体テスト ──────────────────────────────────────────────

// TestYARAListFilter_DefaultLimitIsZero は YARAListFilter のデフォルト Limit がゼロであることを確認する
func TestYARAListFilter_DefaultLimitIsZero(t *testing.T) {
	var f YARAListFilter
	if f.Limit != 0 {
		t.Errorf("YARAListFilter.Limit のデフォルト = %d, want 0", f.Limit)
	}
}

// TestYARAListFilter_EnabledPointerCanBeSet は Enabled ポインタを設定できることを確認する
func TestYARAListFilter_EnabledPointerCanBeSet(t *testing.T) {
	trueVal := true
	f := YARAListFilter{Enabled: &trueVal}
	if f.Enabled == nil {
		t.Fatal("Enabled に true を設定後は nil でないべき")
	}
	if !*f.Enabled {
		t.Error("*Enabled = false, want true")
	}

	falseVal := false
	f2 := YARAListFilter{Enabled: &falseVal}
	if *f2.Enabled {
		t.Error("*Enabled = true, want false")
	}
}

// TestYARAListFilter_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestYARAListFilter_AllFieldsCanBeSet(t *testing.T) {
	enabled := true
	f := YARAListFilter{
		Search:   "ransomware",
		Severity: "high",
		Enabled:  &enabled,
		Limit:    100,
		Offset:   10,
	}
	if f.Search != "ransomware" {
		t.Errorf("Search = %q, want 'ransomware'", f.Search)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", f.Severity)
	}
	if f.Limit != 100 {
		t.Errorf("Limit = %d, want 100", f.Limit)
	}
	if f.Offset != 10 {
		t.Errorf("Offset = %d, want 10", f.Offset)
	}
}

// ─── CreateYARARuleInput デフォルト値テスト ────────────────────────────────────

// TestCreateYARARuleInput_DefaultSeverityEmptyBeforeCreate は入力の Severity がデフォルトで空文字列であることを確認する
func TestCreateYARARuleInput_DefaultSeverityEmptyBeforeCreate(t *testing.T) {
	// Create() は Severity == "" の場合に "medium" を設定するが、
	// 入力構造体自体は空のまま（純粋構造体のゼロ値確認）
	var in CreateYARARuleInput
	if in.Severity != "" {
		t.Errorf("CreateYARARuleInput.Severity のデフォルトは空文字列: got %q", in.Severity)
	}
	if in.Enabled {
		t.Error("CreateYARARuleInput.Enabled のデフォルトは false であるべき")
	}
}

// TestCreateYARARuleInput_TagsNilByDefault は CreateYARARuleInput の Tags がデフォルトで nil であることを確認する
func TestCreateYARARuleInput_TagsNilByDefault(t *testing.T) {
	var in CreateYARARuleInput
	if in.Tags != nil {
		t.Errorf("CreateYARARuleInput.Tags のデフォルトは nil であるべき: got %v", in.Tags)
	}
}

// TestCreateYARARuleInput_AllFieldsAssignable は全フィールドを代入できることを確認する
func TestCreateYARARuleInput_AllFieldsAssignable(t *testing.T) {
	userID := "user-abc"
	in := CreateYARARuleInput{
		Name:        "test_rule",
		Description: "テストルール",
		Content:     "rule test { condition: false }",
		Tags:        []string{"test"},
		Enabled:     true,
		Severity:    "medium",
		CreatedBy:   &userID,
	}
	if in.Name != "test_rule" {
		t.Errorf("Name = %q, want 'test_rule'", in.Name)
	}
	if in.CreatedBy == nil || *in.CreatedBy != userID {
		t.Errorf("CreatedBy = %v, want %q", in.CreatedBy, userID)
	}
}
