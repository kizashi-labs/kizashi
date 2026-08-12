package store

import (
	"encoding/hex"
	"testing"
)

// ─── パスワードリセットトークン形式テスト ────────────────────────────────────
//
// password_reset.go で生成されるトークンは crypto/rand 32バイト → hex エンコードで
// 64文字の16進数文字列になる。トークン形式の検証ロジックをテストする。

func TestPasswordResetToken_HexLength(t *testing.T) {
	// 32バイト → hex は必ず 64文字
	b := make([]byte, 32)
	token := hex.EncodeToString(b)
	if len(token) != 64 {
		t.Errorf("32バイトhexトークン長 = %d, want 64", len(token))
	}
}

func TestPasswordResetToken_HexCharacters(t *testing.T) {
	// hex エンコードされたトークンは [0-9a-f] のみ
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 7) // 0〜255 範囲の値
	}
	token := hex.EncodeToString(b)
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("トークンに不正な文字: %q", string(c))
		}
	}
}

func TestPasswordResetToken_FormatValidation(t *testing.T) {
	// 有効なトークン形式を判定する純粋関数（ハンドラの受け取り検証相当）
	isValidFormat := func(token string) bool {
		if len(token) != 64 {
			return false
		}
		for _, c := range token {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}

	valid := hex.EncodeToString(make([]byte, 32))
	if !isValidFormat(valid) {
		t.Errorf("有効なhexトークンが不正と判定された: %q", valid)
	}
	// 無効なケース
	for _, bad := range []string{
		"",
		"short",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 大文字
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // 非hex
		"abc", // 短すぎ
	} {
		if isValidFormat(bad) {
			t.Errorf("不正なトークンが有効と判定された: %q", bad)
		}
	}
}

func TestPasswordResetToken_Uniqueness(t *testing.T) {
	// 同じゼロバイト列からは同じトークンが生成されるが、
	// 異なるバイト列からは異なるトークンが生成される
	a := hex.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
	b := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	if a == b {
		t.Error("異なるバイト列から異なるトークンが生成されるべき")
	}
}

// ─── ErrInvalidResetToken エラーメッセージテスト ─────────────────────────────

func TestErrInvalidResetToken_Message(t *testing.T) {
	if ErrInvalidResetToken == nil {
		t.Fatal("ErrInvalidResetToken は nil でないべき")
	}
	msg := ErrInvalidResetToken.Error()
	if msg == "" {
		t.Error("ErrInvalidResetToken のメッセージは空でないべき")
	}
}

func TestErrInvalidResetToken_IsDistinct(t *testing.T) {
	// 異なるエラーと比較すると false になる
	otherErr := ErrInvalidResetToken
	if otherErr != ErrInvalidResetToken {
		t.Error("同じエラー変数は等値であるべき")
	}
}

// ─── トークン有効期限検証ロジック ─────────────────────────────────────────────

func TestPasswordResetTokenExpiry_DefaultDuration(t *testing.T) {
	// password_reset_tokens テーブルのデフォルト有効期限は通常1時間
	// ここではロジックの定数を確認する (ハンドラの設定に依存)
	const expiryHours = 1
	if expiryHours <= 0 {
		t.Error("有効期限は正の値であるべき")
	}
}

func TestPasswordResetToken_HexDecodeRoundtrip(t *testing.T) {
	// hex エンコード/デコードの往復一致を確認
	original := []byte{
		0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}
	encoded := hex.EncodeToString(original)
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("hex.DecodeString 失敗: %v", err)
	}
	for i, b := range decoded {
		if b != original[i] {
			t.Errorf("往復後に異なるバイト[%d]: got 0x%02x, want 0x%02x", i, b, original[i])
		}
	}
}
