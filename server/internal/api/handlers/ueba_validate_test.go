package handlers

import "testing"

// ─── min100 ──────────────────────────────────────────────────────────────────

func TestMin100_NormalValue(t *testing.T) {
	if got := min100(50); got != 50 {
		t.Errorf("min100(50) = %d, want 50", got)
	}
}

func TestMin100_Zero(t *testing.T) {
	if got := min100(0); got != 0 {
		t.Errorf("min100(0) = %d, want 0", got)
	}
}

func TestMin100_Exactly100(t *testing.T) {
	if got := min100(100); got != 100 {
		t.Errorf("min100(100) = %d, want 100", got)
	}
}

func TestMin100_Above100_ClampsTo100(t *testing.T) {
	if got := min100(150); got != 100 {
		t.Errorf("min100(150) = %d, want 100", got)
	}
}

func TestMin100_Negative_ClampsTo0(t *testing.T) {
	if got := min100(-10); got != 0 {
		t.Errorf("min100(-10) = %d, want 0", got)
	}
}
