package handlers

import "testing"

// ─── scoreTier ───────────────────────────────────────────────────────────────

func TestScoreTier_Critical(t *testing.T) {
	for _, score := range []int{85, 90, 100} {
		got := scoreTier(score)
		if got != "critical" {
			t.Errorf("scoreTier(%d) = %q, want critical", score, got)
		}
	}
}

func TestScoreTier_High(t *testing.T) {
	for _, score := range []int{65, 70, 84} {
		got := scoreTier(score)
		if got != "high" {
			t.Errorf("scoreTier(%d) = %q, want high", score, got)
		}
	}
}

func TestScoreTier_Medium(t *testing.T) {
	for _, score := range []int{40, 50, 64} {
		got := scoreTier(score)
		if got != "medium" {
			t.Errorf("scoreTier(%d) = %q, want medium", score, got)
		}
	}
}

func TestScoreTier_Low(t *testing.T) {
	for _, score := range []int{0, 1, 20, 39} {
		got := scoreTier(score)
		if got != "low" {
			t.Errorf("scoreTier(%d) = %q, want low", score, got)
		}
	}
}

func TestScoreTier_BoundaryValues(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{84, "high"},
		{85, "critical"},
		{64, "medium"},
		{65, "high"},
		{39, "low"},
		{40, "medium"},
	}
	for _, tc := range cases {
		got := scoreTier(tc.score)
		if got != tc.want {
			t.Errorf("scoreTier(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestScoreTier_AllTiersReachable(t *testing.T) {
	tiers := make(map[string]bool)
	for i := 0; i <= 100; i++ {
		tiers[scoreTier(i)] = true
	}
	for _, tier := range []string{"critical", "high", "medium", "low"} {
		if !tiers[tier] {
			t.Errorf("tier %q がスコア範囲 0-100 で一度も返されませんでした", tier)
		}
	}
}
