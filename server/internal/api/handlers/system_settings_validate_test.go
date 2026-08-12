package handlers

import "testing"

// ─── nilIfEmpty ──────────────────────────────────────────────────────────────

func TestNilIfEmpty_EmptyString_ReturnsNil(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty('') = %v, want nil", got)
	}
}

func TestNilIfEmpty_NonEmpty_ReturnsString(t *testing.T) {
	got := nilIfEmpty("value")
	if got == nil {
		t.Fatal("nilIfEmpty('value') = nil, want non-nil")
	}
	if s, ok := got.(string); !ok || s != "value" {
		t.Errorf("nilIfEmpty('value') = %v, want 'value'", got)
	}
}

func TestNilIfEmpty_Whitespace_ReturnsNonNil(t *testing.T) {
	// whitespace is not empty by this function's definition
	got := nilIfEmpty("  ")
	if got == nil {
		t.Error("nilIfEmpty('  ') = nil, whitespace should not be treated as empty")
	}
}
