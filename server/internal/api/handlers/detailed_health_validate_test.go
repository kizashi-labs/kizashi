package handlers

import (
	"math"
	"testing"
)

func TestRoundTo2dp_IntegerValue_Unchanged(t *testing.T) {
	if got := roundTo2dp(5.0); got != 5.0 {
		t.Errorf("roundTo2dp(5.0) = %v, want 5.0", got)
	}
}

func TestRoundTo2dp_TwoDecimalPlaces_Unchanged(t *testing.T) {
	if got := roundTo2dp(3.14); got != 3.14 {
		t.Errorf("roundTo2dp(3.14) = %v, want 3.14", got)
	}
}

func TestRoundTo2dp_RoundsDown(t *testing.T) {
	got := roundTo2dp(1.234)
	if math.Abs(got-1.23) > 0.001 {
		t.Errorf("roundTo2dp(1.234) = %v, want ~1.23", got)
	}
}

func TestRoundTo2dp_RoundsUp(t *testing.T) {
	got := roundTo2dp(1.235)
	if math.Abs(got-1.24) > 0.001 {
		t.Errorf("roundTo2dp(1.235) = %v, want ~1.24", got)
	}
}

func TestRoundTo2dp_Zero(t *testing.T) {
	if got := roundTo2dp(0.0); got != 0.0 {
		t.Errorf("roundTo2dp(0.0) = %v, want 0.0", got)
	}
}

func TestRoundTo2dp_LargeValue(t *testing.T) {
	got := roundTo2dp(99.999)
	if math.Abs(got-100.0) > 0.001 {
		t.Errorf("roundTo2dp(99.999) = %v, want ~100.0", got)
	}
}
