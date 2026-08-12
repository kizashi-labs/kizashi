package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────
// validatePasswordAgainstPolicy のテスト
// ─────────────────────────────────────────────

func makeDefaultTestPolicy() passwordPolicyRow {
	return passwordPolicyRow{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigits:    true,
		RequireSpecial:   true,
		MinSpecialChars:  1,
	}
}

func TestValidatePasswordAgainstPolicy(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		policy         passwordPolicyRow
		wantViolations int
	}{
		{
			// 完全に有効なパスワード
			name:           "有効なパスワード",
			password:       "Abcdef1!",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 0,
		},
		{
			// 短すぎるパスワード
			name:           "短すぎるパスワード",
			password:       "Ab1!",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// 大文字なし
			name:           "大文字がないパスワード",
			password:       "abcdef1!",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// 小文字なし
			name:           "小文字がないパスワード",
			password:       "ABCDEF1!",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// 数字なし
			name:           "数字がないパスワード",
			password:       "Abcdefg!",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// 特殊文字なし
			name:           "特殊文字がないパスワード",
			password:       "Abcdef12",
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// すべての条件に違反
			name:     "すべての条件に違反",
			password: "ab",
			policy:   makeDefaultTestPolicy(),
			// 短すぎる, 大文字なし, 数字なし, 特殊文字なし (小文字はある)
			wantViolations: 4,
		},
		{
			// MaxLength超過
			name: "最大長超過",
			password: func() string {
				s := make([]byte, 130)
				for i := range s {
					s[i] = 'A'
				}
				// 最低限の要件を満たすために末尾に付加
				s[0] = 'a'
				s[1] = '1'
				s[2] = '!'
				return string(s)
			}(),
			policy:         makeDefaultTestPolicy(),
			wantViolations: 1,
		},
		{
			// MaxLength=0 の場合は上限チェックなし
			name:     "MaxLength=0は上限なし",
			password: "Abcdef1!" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			policy: passwordPolicyRow{
				MinLength:        8,
				MaxLength:        0, // 上限なし
				RequireUppercase: true,
				RequireLowercase: true,
				RequireDigits:    true,
				RequireSpecial:   true,
				MinSpecialChars:  1,
			},
			wantViolations: 0,
		},
		{
			// RequireSpecialがfalseの場合は特殊文字不要
			name:     "RequireSpecial=falseの場合は特殊文字不要",
			password: "Abcdef12",
			policy: passwordPolicyRow{
				MinLength:        8,
				MaxLength:        128,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireDigits:    true,
				RequireSpecial:   false,
			},
			wantViolations: 0,
		},
		{
			// MinSpecialChars=2 で特殊文字が1個しかない場合
			name:     "MinSpecialChars=2で特殊文字1個",
			password: "Abcdef1!",
			policy: passwordPolicyRow{
				MinLength:        8,
				MaxLength:        128,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireDigits:    true,
				RequireSpecial:   true,
				MinSpecialChars:  2,
			},
			wantViolations: 1,
		},
		{
			// すべての要件が無効な緩いポリシー
			name:     "緩いポリシー（要件なし）",
			password: "abc",
			policy: passwordPolicyRow{
				MinLength:        1,
				MaxLength:        0,
				RequireUppercase: false,
				RequireLowercase: false,
				RequireDigits:    false,
				RequireSpecial:   false,
			},
			wantViolations: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := validatePasswordAgainstPolicy(tc.password, tc.policy)
			if len(violations) != tc.wantViolations {
				t.Errorf("violation count = %d, want %d; violations: %v",
					len(violations), tc.wantViolations, violations)
			}
		})
	}
}

// ─────────────────────────────────────────────
// validateNewPassword のテスト
// ─────────────────────────────────────────────

func TestValidateNewPassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{
			// 有効: 8文字以上かつ英字と数字を含む
			name:    "有効なパスワード",
			pw:      "Hello123",
			wantErr: false,
		},
		{
			// 有効: 特殊文字も含む
			name:    "特殊文字を含む有効なパスワード",
			pw:      "P@ssw0rd!",
			wantErr: false,
		},
		{
			// 短すぎる (7文字)
			name:    "7文字は無効",
			pw:      "Abc123x",
			wantErr: true,
		},
		{
			// ちょうど8文字で有効
			name:    "8文字は有効（境界値）",
			pw:      "Abcde123",
			wantErr: false,
		},
		{
			// 数字なし
			name:    "数字なし",
			pw:      "Abcdefgh",
			wantErr: true,
		},
		{
			// 英字なし (数字のみ)
			name:    "英字なし（数字のみ）",
			pw:      "12345678",
			wantErr: true,
		},
		{
			// 空文字列
			name:    "空文字列",
			pw:      "",
			wantErr: true,
		},
		{
			// 日本語文字は unicode.IsLetter で英字扱いになる
			name:    "日本語+数字は有効（IsLetterの挙動）",
			pw:      "パスワード123",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNewPassword(tc.pw)
			if tc.wantErr && err == nil {
				t.Errorf("エラーが期待されましたが nil でした (pw=%q)", tc.pw)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("エラーは期待されていませんでしたが %v でした (pw=%q)", err, tc.pw)
			}
		})
	}
}

// ppItoa のユニットテスト（内部ユーティリティ）
func TestPpItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{128, "128"},
		{-1, "-1"},
		{-99, "-99"},
	}
	for _, tc := range tests {
		got := ppItoa(tc.input)
		if got != tc.want {
			t.Errorf("ppItoa(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
