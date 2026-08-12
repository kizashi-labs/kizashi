package handlers

import (
	"strings"
	"testing"
)

// ─── generateRecoveryCodes ───────────────────────────────────────────────────

func TestGenerateRecoveryCodes_Returns10Codes(t *testing.T) {
	codes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatalf("generateRecoveryCodes: err = %v", err)
	}
	if len(codes) != 10 {
		t.Errorf("generateRecoveryCodes: len = %d, want 10", len(codes))
	}
}

func TestGenerateRecoveryCodes_Format(t *testing.T) {
	codes, _ := generateRecoveryCodes()
	for _, c := range codes {
		// Format: XXXX-XXXX-XXXX (4-4-4 hex)
		parts := strings.Split(c, "-")
		if len(parts) != 3 {
			t.Errorf("generateRecoveryCodes: code %q should have 3 parts", c)
		}
		for _, p := range parts {
			if len(p) != 4 {
				t.Errorf("generateRecoveryCodes: part %q should be 4 chars", p)
			}
		}
	}
}

func TestGenerateRecoveryCodes_Unique(t *testing.T) {
	codes, _ := generateRecoveryCodes()
	seen := make(map[string]bool)
	for _, c := range codes {
		if seen[c] {
			t.Errorf("generateRecoveryCodes: duplicate code %q", c)
		}
		seen[c] = true
	}
}

// ─── hashCode ─────────────────────────────────────────────────────────────────

func TestHashCode_Deterministic(t *testing.T) {
	a := hashCode("test-code")
	b := hashCode("test-code")
	if a != b {
		t.Errorf("hashCode: same input produced different output: %q != %q", a, b)
	}
}

func TestHashCode_DifferentInputs_DifferentOutput(t *testing.T) {
	a := hashCode("code1")
	b := hashCode("code2")
	if a == b {
		t.Error("hashCode: different inputs should produce different hashes")
	}
}

func TestHashCode_IsSHA256Hex(t *testing.T) {
	h := hashCode("test")
	if len(h) != 64 {
		t.Errorf("hashCode: len = %d, want 64 (SHA-256 hex)", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hashCode: non-hex character %q in output", c)
			break
		}
	}
}
