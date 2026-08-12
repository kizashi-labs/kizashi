package handlers

import "testing"

// ─── itoa ─────────────────────────────────────────────────────────────────────

func TestItoa_Zero(t *testing.T) {
	if got := itoa(0); got != "0" {
		t.Errorf("itoa(0) = %q, want '0'", got)
	}
}

func TestItoa_Positive(t *testing.T) {
	if got := itoa(42); got != "42" {
		t.Errorf("itoa(42) = %q, want '42'", got)
	}
}

func TestItoa_Negative(t *testing.T) {
	if got := itoa(-1); got != "-1" {
		t.Errorf("itoa(-1) = %q, want '-1'", got)
	}
}

func TestItoa_LargeNumber(t *testing.T) {
	if got := itoa(1000000); got != "1000000" {
		t.Errorf("itoa(1000000) = %q, want '1000000'", got)
	}
}
