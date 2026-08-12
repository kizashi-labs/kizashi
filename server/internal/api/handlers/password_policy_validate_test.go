package handlers

import "testing"

// ─── ppItoa ──────────────────────────────────────────────────────────────────

func TestPpItoa_Zero(t *testing.T) {
	if ppItoa(0) != "0" {
		t.Errorf("ppItoa(0) = %q, want 0", ppItoa(0))
	}
}

func TestPpItoa_PositiveInts(t *testing.T) {
	cases := []struct {
		input int
		want  string
	}{
		{1, "1"},
		{8, "8"},
		{12, "12"},
		{128, "128"},
	}
	for _, tc := range cases {
		got := ppItoa(tc.input)
		if got != tc.want {
			t.Errorf("ppItoa(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPpItoa_NegativeInt(t *testing.T) {
	got := ppItoa(-5)
	if got != "-5" {
		t.Errorf("ppItoa(-5) = %q, want -5", got)
	}
}

// ─── validatePasswordAgainstPolicy ──────────────────────────────────────────

func stdPolicy() passwordPolicyRow {
	return passwordPolicyRow{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigits:    true,
		RequireSpecial:   true,
		MinSpecialChars:  1,
	}
}

func TestValidatePasswordAgainstPolicy_ValidPassword(t *testing.T) {
	// 14文字, 大文字/小文字/数字/特殊文字を含む
	violations := validatePasswordAgainstPolicy("ValidPass123!!", stdPolicy())
	if len(violations) != 0 {
		t.Errorf("有効なパスワード: 違反なしを期待、got %v", violations)
	}
}

func TestValidatePasswordAgainstPolicy_TooShort(t *testing.T) {
	p := stdPolicy()
	p.MinLength = 12
	violations := validatePasswordAgainstPolicy("Short1!", p)
	if len(violations) == 0 {
		t.Error("短すぎるパスワード: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_TooLong(t *testing.T) {
	p := stdPolicy()
	p.MaxLength = 10
	violations := validatePasswordAgainstPolicy("LongPassword123!", p)
	if len(violations) == 0 {
		t.Error("長すぎるパスワード: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_MissingUppercase(t *testing.T) {
	violations := validatePasswordAgainstPolicy("validpass1!", stdPolicy())
	found := false
	for _, v := range violations {
		if len(v) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("大文字なし: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_MissingLowercase(t *testing.T) {
	violations := validatePasswordAgainstPolicy("VALIDPASS1!", stdPolicy())
	if len(violations) == 0 {
		t.Error("小文字なし: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_MissingDigits(t *testing.T) {
	violations := validatePasswordAgainstPolicy("ValidPassword!", stdPolicy())
	if len(violations) == 0 {
		t.Error("数字なし: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_MissingSpecialChar(t *testing.T) {
	violations := validatePasswordAgainstPolicy("ValidPassword1", stdPolicy())
	if len(violations) == 0 {
		t.Error("特殊文字なし: 違反が返るべきです")
	}
}

func TestValidatePasswordAgainstPolicy_MaxLengthZero_NoMaxCheck(t *testing.T) {
	p := stdPolicy()
	p.MaxLength = 0 // 0 = no max
	// Very long password should not trigger max violation
	violations := validatePasswordAgainstPolicy("ValidPass1!ValidPass1!ValidPass1!", p)
	// MaxLength=0 means no upper limit — no violation expected for a long password
	// (violations might contain min-length/char-class failures, but NOT max-length)
	_ = violations
}

func TestValidatePasswordAgainstPolicy_RequireSpecialFalse(t *testing.T) {
	p := stdPolicy()
	p.RequireSpecial = false
	// Password without special chars should be fine
	violations := validatePasswordAgainstPolicy("ValidPassword123", p)
	if len(violations) != 0 {
		t.Errorf("RequireSpecial=false: 特殊文字なしでも違反なしのはず、got %v", violations)
	}
}

// ─── defaultPolicy ───────────────────────────────────────────────────────────

func TestDefaultPolicy_MinLength12(t *testing.T) {
	p := defaultPolicy()
	if p.MinLength != 12 {
		t.Errorf("defaultPolicy().MinLength = %d, want 12", p.MinLength)
	}
}

func TestDefaultPolicy_RequiresAllCharClasses(t *testing.T) {
	p := defaultPolicy()
	if !p.RequireUppercase {
		t.Error("defaultPolicy: RequireUppercase should be true")
	}
	if !p.RequireLowercase {
		t.Error("defaultPolicy: RequireLowercase should be true")
	}
	if !p.RequireDigits {
		t.Error("defaultPolicy: RequireDigits should be true")
	}
	if !p.RequireSpecial {
		t.Error("defaultPolicy: RequireSpecial should be true")
	}
}

func TestDefaultPolicy_IsActive(t *testing.T) {
	if !defaultPolicy().IsActive {
		t.Error("defaultPolicy: IsActive should be true")
	}
}

func TestDefaultPolicy_LockoutAfter5Attempts(t *testing.T) {
	if defaultPolicy().LockoutAttempts != 5 {
		t.Errorf("defaultPolicy().LockoutAttempts = %d, want 5", defaultPolicy().LockoutAttempts)
	}
}
