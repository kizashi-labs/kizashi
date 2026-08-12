package handlers

import (
	"testing"
	"time"
)

// ─── asDuration / secondsToDuration ──────────────────────────────────────────

func TestAsDuration_Zero(t *testing.T) {
	if got := asDuration(0); got != 0 {
		t.Errorf("asDuration(0) = %v, want 0", got)
	}
}

func TestAsDuration_OneSecond(t *testing.T) {
	if got := asDuration(1); got != time.Second {
		t.Errorf("asDuration(1) = %v, want 1s", got)
	}
}

func TestAsDuration_OneMinute(t *testing.T) {
	if got := asDuration(60); got != time.Minute {
		t.Errorf("asDuration(60) = %v, want 1m", got)
	}
}

func TestAsDuration_OneHour(t *testing.T) {
	if got := asDuration(3600); got != time.Hour {
		t.Errorf("asDuration(3600) = %v, want 1h", got)
	}
}

func TestSecondsToDuration_Zero(t *testing.T) {
	if got := secondsToDuration(0); got != 0 {
		t.Errorf("secondsToDuration(0) = %v, want 0", got)
	}
}

func TestSecondsToDuration_EqualsAsDuration(t *testing.T) {
	for _, s := range []int64{1, 60, 3600, 86400} {
		a := asDuration(s)
		b := secondsToDuration(s)
		if a != b {
			t.Errorf("asDuration(%d)=%v != secondsToDuration(%d)=%v", s, a, s, b)
		}
	}
}
