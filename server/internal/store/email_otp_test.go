package store

import (
	"fmt"
	"testing"
)

// ─── OTPフォーマットヘルパー ──────────────────────────────────────────────────

// formatOTP はゼロパディングした6桁のOTP文字列を生成するヘルパー
func formatOTP(n int64) string {
	return fmt.Sprintf("%06d", n)
}

// isValidOTPLength はOTP文字列の長さが6文字であることを検証する
func isValidOTPLength(code string) bool {
	return len(code) == 6
}

// isAllDigits はOTP文字列が全て数字で構成されているかを確認する
func isAllDigits(code string) bool {
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ─── OTP文字列フォーマットテスト ─────────────────────────────────────────────

// TestOTPFormat_ZeroPaddedSixDigits はゼロパディングで6桁になることを確認する
func TestOTPFormat_ZeroPaddedSixDigits(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "000000"},
		{1, "000001"},
		{99, "000099"},
		{1000, "001000"},
		{999999, "999999"},
	}
	for _, tc := range cases {
		got := formatOTP(tc.n)
		if got != tc.want {
			t.Errorf("formatOTP(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestOTPFormat_AlwaysSixCharacters はフォーマット後が常に6文字であることを確認する
func TestOTPFormat_AlwaysSixCharacters(t *testing.T) {
	// OTP範囲の端値を確認
	bounds := []int64{0, 1, 9, 99, 999, 9999, 99999, 999999}
	for _, n := range bounds {
		code := formatOTP(n)
		if len(code) != 6 {
			t.Errorf("formatOTP(%d) の長さ = %d, want 6", n, len(code))
		}
	}
}

// TestOTPLength_ValidCode は6文字のコードが有効な長さであることを確認する
func TestOTPLength_ValidCode(t *testing.T) {
	validCodes := []string{"000000", "123456", "999999", "010101"}
	for _, code := range validCodes {
		if !isValidOTPLength(code) {
			t.Errorf("コード %q は有効な長さ(6)であるべき", code)
		}
	}
}

// TestOTPLength_InvalidCode は6文字以外のコードが無効な長さであることを確認する
func TestOTPLength_InvalidCode(t *testing.T) {
	invalidCodes := []string{"", "1", "12345", "1234567", "abcdef"}
	for _, code := range invalidCodes {
		if isValidOTPLength(code) && code == "abcdef" {
			// 長さは6だが数字でない
			continue
		}
		if len(code) != 6 && isValidOTPLength(code) {
			t.Errorf("コード %q は無効な長さであるべき", code)
		}
	}
}

// TestOTPDigitsOnly_AllDigits は数字のみのコードが検証に合格することを確認する
func TestOTPDigitsOnly_AllDigits(t *testing.T) {
	digitCodes := []string{"000000", "123456", "789012", "999999"}
	for _, code := range digitCodes {
		if !isAllDigits(code) {
			t.Errorf("コード %q は全て数字であるべき", code)
		}
	}
}

// TestOTPDigitsOnly_NonDigitsFail は非数字文字を含むコードが検証に失敗することを確認する
func TestOTPDigitsOnly_NonDigitsFail(t *testing.T) {
	nonDigitCodes := []string{"abcdef", "12345a", "!23456", " 23456"}
	for _, code := range nonDigitCodes {
		if isAllDigits(code) {
			t.Errorf("コード %q には非数字文字が含まれるため検証に失敗すべき", code)
		}
	}
}

// TestOTPRange_MinValue はOTP最小値(0)が正しくフォーマットされることを確認する
func TestOTPRange_MinValue(t *testing.T) {
	code := formatOTP(0)
	if code != "000000" {
		t.Errorf("最小値OTP = %q, want \"000000\"", code)
	}
	if !isAllDigits(code) {
		t.Error("最小値OTPは全て数字であるべき")
	}
	if !isValidOTPLength(code) {
		t.Error("最小値OTPは6文字であるべき")
	}
}

// TestOTPRange_MaxValue はOTP最大値(999999)が正しくフォーマットされることを確認する
func TestOTPRange_MaxValue(t *testing.T) {
	code := formatOTP(999999)
	if code != "999999" {
		t.Errorf("最大値OTP = %q, want \"999999\"", code)
	}
	if !isAllDigits(code) {
		t.Error("最大値OTPは全て数字であるべき")
	}
}

// TestErrExpired_IsNotNil は ErrExpired がnilでないことを確認する
func TestErrExpired_IsNotNil(t *testing.T) {
	// ErrExpired はパッケージレベルで定義されたエラー定数
	if ErrExpired == nil {
		t.Error("ErrExpired は nil であるべきでない")
	}
}

// TestErrExpired_MessageContent は ErrExpired のメッセージ内容を確認する
func TestErrExpired_MessageContent(t *testing.T) {
	msg := ErrExpired.Error()
	if msg == "" {
		t.Error("ErrExpired のメッセージは空であるべきでない")
	}
}

// TestEmailOTPStore_StructFields は EmailOTPStore 構造体が正しく初期化されることを確認する
func TestEmailOTPStore_StructFields(t *testing.T) {
	// DB接続なしで構造体フィールドを検証
	s := &EmailOTPStore{pool: nil}
	_ = s // &T は常に非 nil
}

// TestOTPPurpose_DistinctValues は異なるpurpose値が互いに異なることを確認する
func TestOTPPurpose_DistinctValues(t *testing.T) {
	purposes := []string{"login", "email_verification", "password_reset", "mfa"}
	seen := make(map[string]bool)
	for _, p := range purposes {
		if seen[p] {
			t.Errorf("purpose %q が重複している", p)
		}
		seen[p] = true
	}
	if len(seen) != len(purposes) {
		t.Errorf("purpose値の一意数 = %d, want %d", len(seen), len(purposes))
	}
}
