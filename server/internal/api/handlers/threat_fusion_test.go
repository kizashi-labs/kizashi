package handlers

import (
	"testing"
	"time"
)

func TestReliabilityLabel(t *testing.T) {
	cases := map[int]string{0: "low", 99: "low", 100: "medium", 999: "medium", 1000: "high", 5000: "high"}
	for in, want := range cases {
		if got := reliabilityLabel(in); got != want {
			t.Errorf("reliabilityLabel(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFreshnessScore(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		ts   *time.Time
		want int
	}{
		{"nil", nil, 0},
		{"1h", ptrTime(now.Add(-1 * time.Hour)), 100},
		{"3d", ptrTime(now.Add(-3 * 24 * time.Hour)), 70},
		{"10d", ptrTime(now.Add(-10 * 24 * time.Hour)), 40},
		{"60d", ptrTime(now.Add(-60 * 24 * time.Hour)), 10},
	}
	for _, tc := range cases {
		if got := freshnessScore(tc.ts); got != tc.want {
			t.Errorf("%s: freshnessScore = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestAptStatus(t *testing.T) {
	cases := map[string]string{"active": "active", "monitoring": "suspected", "inactive": "concluded", "": "active", "x": "active"}
	for in, want := range cases {
		if got := aptStatus(in); got != want {
			t.Errorf("aptStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfidenceFromSeverity(t *testing.T) {
	cases := map[string]int{"critical": 90, "high": 75, "medium": 50, "low": 30, "": 50}
	for in, want := range cases {
		if got := confidenceFromSeverity(in); got != want {
			t.Errorf("confidenceFromSeverity(%q) = %d, want %d", in, got, want)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
