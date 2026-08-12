package detectionmetrics

import "testing"

func findRec(recs []TuningRecommendation, rule string) (TuningRecommendation, bool) {
	for _, r := range recs {
		if r.RuleName == rule {
			return r, true
		}
	}
	return TuningRecommendation{}, false
}

func TestRecommendTuning_Actions(t *testing.T) {
	stats := []RuleStat{
		{RuleName: "noisy-suppress", FPCount: 90, TotalCount: 100, FPRate: 0.90}, // suppress
		{RuleName: "noisy-downgrade", FPCount: 15, TotalCount: 25, FPRate: 0.60}, // downgrade
		{RuleName: "noisy-review", FPCount: 4, TotalCount: 12, FPRate: 0.333},    // review
		{RuleName: "clean", FPCount: 1, TotalCount: 100, FPRate: 0.01},           // none
		{RuleName: "low-volume", FPCount: 2, TotalCount: 2, FPRate: 1.0},         // none (volume gate)
	}
	recs := RecommendTuning(stats)

	if r, ok := findRec(recs, "noisy-suppress"); !ok || r.Action != ActionSuppress {
		t.Errorf("noisy-suppress: want %q, got %+v (found=%v)", ActionSuppress, r, ok)
	}
	if r, ok := findRec(recs, "noisy-downgrade"); !ok || r.Action != ActionDowngrade {
		t.Errorf("noisy-downgrade: want %q, got %+v (found=%v)", ActionDowngrade, r, ok)
	}
	if r, ok := findRec(recs, "noisy-review"); !ok || r.Action != ActionReview {
		t.Errorf("noisy-review: want %q, got %+v (found=%v)", ActionReview, r, ok)
	}
	if _, ok := findRec(recs, "clean"); ok {
		t.Error("clean rule should produce no recommendation")
	}
	if _, ok := findRec(recs, "low-volume"); ok {
		t.Error("low-volume all-FP rule should be gated out (not enough evidence)")
	}
}

func TestRecommendTuning_RankedByVolume(t *testing.T) {
	stats := []RuleStat{
		{RuleName: "small", FPCount: 12, TotalCount: 15, FPRate: 0.80},
		{RuleName: "big", FPCount: 200, TotalCount: 220, FPRate: 0.91},
		{RuleName: "mid", FPCount: 50, TotalCount: 60, FPRate: 0.83},
	}
	recs := RecommendTuning(stats)
	if len(recs) != 3 {
		t.Fatalf("want 3 recommendations, got %d", len(recs))
	}
	// Ranked by FP volume, biggest analyst-time sink first.
	if recs[0].RuleName != "big" || recs[1].RuleName != "mid" || recs[2].RuleName != "small" {
		t.Errorf("ranking wrong: %s, %s, %s", recs[0].RuleName, recs[1].RuleName, recs[2].RuleName)
	}
}

func TestRecommendTuning_DerivesRateWhenZero(t *testing.T) {
	// FPRate left at 0 (not precomputed) → derived from counts.
	stats := []RuleStat{{RuleName: "r", FPCount: 90, TotalCount: 100}}
	recs := RecommendTuning(stats)
	if len(recs) != 1 || recs[0].Action != ActionSuppress {
		t.Fatalf("expected suppress from derived rate, got %+v", recs)
	}
	if recs[0].FPRate < 0.89 || recs[0].FPRate > 0.91 {
		t.Errorf("derived FPRate = %.3f, want ~0.90", recs[0].FPRate)
	}
}

func TestRecommendTuning_Empty(t *testing.T) {
	if r := RecommendTuning(nil); len(r) != 0 {
		t.Errorf("nil stats should yield no recommendations, got %d", len(r))
	}
}
