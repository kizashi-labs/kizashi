package handlers

import "testing"

// ─── generateVerificationToken ───────────────────────────────────────────────

func TestGenerateVerificationToken_ReturnsNonEmpty(t *testing.T) {
	tok, err := generateVerificationToken()
	if err != nil {
		t.Fatalf("generateVerificationToken: err = %v", err)
	}
	if tok == "" {
		t.Error("generateVerificationToken: returned empty string")
	}
}

func TestGenerateVerificationToken_Is64HexChars(t *testing.T) {
	tok, _ := generateVerificationToken()
	// 32 bytes → 64 hex chars
	if len(tok) != 64 {
		t.Errorf("generateVerificationToken: len = %d, want 64", len(tok))
	}
}

func TestGenerateVerificationToken_Unique(t *testing.T) {
	a, _ := generateVerificationToken()
	b, _ := generateVerificationToken()
	if a == b {
		t.Error("generateVerificationToken: produced duplicate tokens")
	}
}
