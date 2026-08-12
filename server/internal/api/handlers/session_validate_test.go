package handlers

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ─── hashToken ───────────────────────────────────────────────────────────────

func TestHashToken_ReturnsSHA256HexString(t *testing.T) {
	got := hashToken("my-jwt-token")
	// SHA-256 hex is always 64 chars
	if len(got) != 64 {
		t.Errorf("hashToken: len = %d, want 64", len(got))
	}
	// Must be valid hex
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("hashToken: result %q is not valid hex: %v", got, err)
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "some-session-token"
	a := hashToken(token)
	b := hashToken(token)
	if a != b {
		t.Errorf("hashToken: 同じ入力で異なる結果 (%q vs %q)", a, b)
	}
}

func TestHashToken_DifferentInputs_DifferentOutputs(t *testing.T) {
	a := hashToken("token-A")
	b := hashToken("token-B")
	if a == b {
		t.Error("hashToken: 異なるトークンが同じハッシュを返しました")
	}
}

func TestHashToken_EmptyString(t *testing.T) {
	got := hashToken("")
	if len(got) != 64 {
		t.Errorf("hashToken(''): len = %d, want 64", len(got))
	}
	// SHA-256 of "" is e3b0c44298fc1c149afb...
	if !strings.HasPrefix(got, "e3b0c4") {
		t.Errorf("hashToken(''): unexpected value %q", got)
	}
}

func TestHashToken_LowercaseHex(t *testing.T) {
	got := hashToken("test")
	if got != strings.ToLower(got) {
		t.Errorf("hashToken: hex出力はすべて小文字のはず、got %q", got)
	}
}
