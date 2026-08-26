package store

import (
	"strings"
	"testing"
)

// ─── テスト用ヘルパー ─────────────────────────────────────────────────────────

// newStrictPolicy は全ての制約を有効にしたデフォルトポリシーを返す
func newStrictPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}
}

// newLenOnlyPolicy は最低文字数のみを要求するポリシーを返す
func newLenOnlyPolicy(minLen int) *PasswordPolicy {
	return &PasswordPolicy{MinLength: minLen}
}

// pps は PasswordPolicyStore のインスタンス（pool不要 — Validateはpureメソッド）
var pps = &PasswordPolicyStore{}

// ─── Validate ────────────────────────────────────────────────────────────────

// TestValidate_CompliantPassword は全ての要件を満たすパスワードが合格することを確認する
func TestValidate_CompliantPassword(t *testing.T) {
	policy := newStrictPolicy()
	err := pps.Validate("StrongPass1!", policy)
	if err != nil {
		t.Errorf("ポリシーを満たすパスワードはエラーなしのはず: got %v", err)
	}
}

// TestValidate_TooShort は最低文字数未満のパスワードが拒否されることを確認する
func TestValidate_TooShort(t *testing.T) {
	policy := newLenOnlyPolicy(10)
	err := pps.Validate("Short1!", policy)
	if err == nil {
		t.Error("短すぎるパスワードはエラーになるべき")
	}
	if !strings.Contains(err.Error(), "文字以上") {
		t.Errorf("エラーメッセージに文字数要件が含まれるべき: %v", err)
	}
}

// TestValidate_ExactMinLength は最低文字数ぴったりのパスワードが合格することを確認する
func TestValidate_ExactMinLength(t *testing.T) {
	policy := newLenOnlyPolicy(8)
	// 8文字ちょうど、大文字小文字数字特殊文字は不要
	err := pps.Validate("abcdefgh", policy)
	if err != nil {
		t.Errorf("最低文字数ちょうどのパスワードはエラーなしのはず: got %v", err)
	}
}

// TestValidate_MissingUppercase は大文字がないパスワードが拒否されることを確認する
func TestValidate_MissingUppercase(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 8, RequireUppercase: true}
	err := pps.Validate("alllower1!", policy)
	if err == nil {
		t.Error("大文字なしパスワードはエラーになるべき")
	}
	if !strings.Contains(err.Error(), "大文字") {
		t.Errorf("エラーメッセージに大文字の要件が含まれるべき: %v", err)
	}
}

// TestValidate_MissingLowercase は小文字がないパスワードが拒否されることを確認する
func TestValidate_MissingLowercase(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 8, RequireLowercase: true}
	err := pps.Validate("ALLUPPER1!", policy)
	if err == nil {
		t.Error("小文字なしパスワードはエラーになるべき")
	}
	if !strings.Contains(err.Error(), "小文字") {
		t.Errorf("エラーメッセージに小文字の要件が含まれるべき: %v", err)
	}
}

// TestValidate_MissingNumber は数字がないパスワードが拒否されることを確認する
func TestValidate_MissingNumber(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 8, RequireNumber: true}
	err := pps.Validate("NoNumbers!", policy)
	if err == nil {
		t.Error("数字なしパスワードはエラーになるべき")
	}
	if !strings.Contains(err.Error(), "数字") {
		t.Errorf("エラーメッセージに数字の要件が含まれるべき: %v", err)
	}
}

// TestValidate_MissingSpecial は記号がないパスワードが拒否されることを確認する
func TestValidate_MissingSpecial(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 8, RequireSpecial: true}
	err := pps.Validate("NoSymbol1", policy)
	if err == nil {
		t.Error("記号なしパスワードはエラーになるべき")
	}
	if !strings.Contains(err.Error(), "記号") {
		t.Errorf("エラーメッセージに記号の要件が含まれるべき: %v", err)
	}
}

// TestValidate_MultipleViolationsReportedTogether は複数違反が1回のエラーに集約されることを確認する
func TestValidate_MultipleViolationsReportedTogether(t *testing.T) {
	// 大文字・数字・記号すべてなし＋短すぎる
	policy := newStrictPolicy()
	err := pps.Validate("ab", policy)
	if err == nil {
		t.Fatal("複数の違反があるパスワードはエラーになるべき")
	}
	// エラーメッセージにセミコロン区切りで複数の違反が含まれるはず
	msg := err.Error()
	if !strings.Contains(msg, ";") {
		t.Errorf("複数違反はセミコロンで区切られるべき: %q", msg)
	}
}

// TestValidate_EmptyPasswordViolatesAll は空文字列が全ての制約に違反することを確認する
func TestValidate_EmptyPasswordViolatesAll(t *testing.T) {
	policy := newStrictPolicy()
	err := pps.Validate("", policy)
	if err == nil {
		t.Error("空パスワードはエラーになるべき")
	}
}

// TestValidate_NoConstraints はポリシーが何も要求しない場合に任意のパスワードが合格することを確認する
func TestValidate_NoConstraints(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 0}
	// 制約なし — 空文字列も合格
	if err := pps.Validate("", policy); err != nil {
		t.Errorf("制約なしの場合、空文字列はエラーなしのはず: got %v", err)
	}
	if err := pps.Validate("anything", policy); err != nil {
		t.Errorf("制約なしの場合、任意の文字列はエラーなしのはず: got %v", err)
	}
}

// ─── Violations ──────────────────────────────────────────────────────────────

// TestViolations_CompliantPasswordReturnsEmpty は合格パスワードの違反リストが空であることを確認する
func TestViolations_CompliantPasswordReturnsEmpty(t *testing.T) {
	policy := newStrictPolicy()
	violations := pps.Violations("StrongPass1!", policy)
	if len(violations) != 0 {
		t.Errorf("合格パスワードは違反なしのはず: got %v", violations)
	}
}

// TestViolations_ShortPasswordReturnsLengthViolation は短いパスワードに長さ違反が返ることを確認する
func TestViolations_ShortPasswordReturnsLengthViolation(t *testing.T) {
	policy := newLenOnlyPolicy(16)
	violations := pps.Violations("short", policy)
	if len(violations) == 0 {
		t.Fatal("短いパスワードは少なくとも1つの違反を返すべき")
	}
	if !strings.Contains(violations[0], "文字以上") {
		t.Errorf("最初の違反は文字数に関するものであるべき: %q", violations[0])
	}
}

// TestViolations_CountMatchesActualViolations は違反の数が実際の問題数と一致することを確認する
func TestViolations_CountMatchesActualViolations(t *testing.T) {
	// 大文字・小文字・数字・記号すべて必須、かつ最低12文字
	policy := newStrictPolicy()
	// "aa" は長さ不足(1) + 大文字なし(2) + 数字なし(3) + 記号なし(4) で4違反
	violations := pps.Violations("aa", policy)
	if len(violations) != 4 {
		t.Errorf("違反数 = %d, want 4 (長さ+大文字+数字+記号): %v", len(violations), violations)
	}
}

// TestViolations_OnlyUppercaseRequired は大文字のみ必須ポリシーでの違反数を確認する
func TestViolations_OnlyUppercaseRequired(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 1, RequireUppercase: true}
	// 大文字なし → 1違反
	violations := pps.Violations("alllower", policy)
	if len(violations) != 1 {
		t.Errorf("大文字なし違反のみ1件のはず: got %v", violations)
	}
}

// TestViolations_SpecialCharactersRecognized は記号が正しく認識されることを確認する
func TestViolations_SpecialCharactersRecognized(t *testing.T) {
	policy := &PasswordPolicy{MinLength: 1, RequireSpecial: true}
	// 各種記号が記号として認識されるか確認
	specialChars := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "="}
	for _, ch := range specialChars {
		v := pps.Violations("Password"+ch, policy)
		if len(v) != 0 {
			t.Errorf("記号 %q は特殊文字として認識されるべき: violations=%v", ch, v)
		}
	}
}

// TestViolations_NilPolicyFieldsDefaultToFalse は bool フィールドのゼロ値が false となり制約なしになることを確認する
func TestViolations_NilPolicyFieldsDefaultToFalse(t *testing.T) {
	// ゼロ値ポリシー — 何も要求しない
	policy := &PasswordPolicy{}
	violations := pps.Violations("simple", policy)
	if len(violations) != 0 {
		t.Errorf("ゼロ値ポリシーは違反なしのはず: got %v", violations)
	}
}

// TestViolations_ReturnsNilSliceOrEmptyOnCompliance は合格時に nil または空スライスが返ることを確認する
func TestViolations_ReturnsNilSliceOrEmptyOnCompliance(t *testing.T) {
	policy := newLenOnlyPolicy(4)
	violations := pps.Violations("abcd", policy)
	// nil も長さ0も「違反なし」として受け入れる
	if len(violations) != 0 {
		t.Errorf("合格パスワードは空スライスを返すべき: got %v", violations)
	}
}

// ─── PasswordPolicy 構造体テスト ─────────────────────────────────────────────

// TestPasswordPolicy_DefaultValues は PasswordPolicy のゼロ値を確認する
func TestPasswordPolicy_DefaultValues(t *testing.T) {
	var p PasswordPolicy
	if p.MinLength != 0 {
		t.Errorf("MinLength のデフォルト = %d, want 0", p.MinLength)
	}
	if p.RequireUppercase {
		t.Error("RequireUppercase のデフォルトは false であるべき")
	}
	if p.RequireLowercase {
		t.Error("RequireLowercase のデフォルトは false であるべき")
	}
	if p.RequireNumber {
		t.Error("RequireNumber のデフォルトは false であるべき")
	}
	if p.RequireSpecial {
		t.Error("RequireSpecial のデフォルトは false であるべき")
	}
}

// TestPasswordPolicy_FieldAssignment は PasswordPolicy への代入が正しく反映されることを確認する
func TestPasswordPolicy_FieldAssignment(t *testing.T) {
	p := PasswordPolicy{
		MinLength:        16,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
		MaxAgeDays:       90,
		HistoryCount:     5,
	}
	if p.MinLength != 16 {
		t.Errorf("MinLength = %d, want 16", p.MinLength)
	}
	if p.MaxAgeDays != 90 {
		t.Errorf("MaxAgeDays = %d, want 90", p.MaxAgeDays)
	}
	if p.HistoryCount != 5 {
		t.Errorf("HistoryCount = %d, want 5", p.HistoryCount)
	}
	if !p.RequireUppercase || !p.RequireLowercase || !p.RequireNumber || !p.RequireSpecial {
		t.Error("全ての require フラグが true であるべき")
	}
}
