package detectionmetrics

// tuning.go — data-driven false-positive tuning recommendations.
//
// A noisy rule is not just an annoyance: analysts silence rules that cry wolf, and a
// silenced rule detects nothing — so uncontrolled false positives quietly LOWER the
// effective detection rate. The Tracker already computes per-rule FP statistics; this
// turns those numbers into ranked, actionable recommendations (suppress / downgrade /
// review) so the noisiest rules are tuned before an analyst disables them outright.
//
// Recommendations are advisory by design — they never auto-disable a rule (a rule with a
// high FP rate may still be the only thing catching a real, rare attack). The output is
// meant for operator review, surfaced alongside the metrics.

import "sort"

// TuningAction is the recommended remediation for a noisy rule.
type TuningAction string

const (
	// ActionSuppress: overwhelmingly false — a strong candidate for a suppression rule
	// or a tightened condition. High FP rate AND enough volume to be confident.
	ActionSuppress TuningAction = "suppress"
	// ActionDowngrade: noisy but not overwhelmingly so — lower its severity or add a
	// scoped exception rather than remove it.
	ActionDowngrade TuningAction = "downgrade"
	// ActionReview: elevated FP rate worth a human look before it worsens.
	ActionReview TuningAction = "review"
)

// TuningRecommendation is a single ranked tuning suggestion for one rule.
type TuningRecommendation struct {
	RuleName   string       `json:"rule_name"`
	FPCount    int          `json:"fp_count"`
	TotalCount int          `json:"total_count"`
	FPRate     float64      `json:"fp_rate"` // 0-1
	Action     TuningAction `json:"action"`
	Rationale  string       `json:"rationale"`
}

// Tuning thresholds. Volume gates avoid recommending action on a rule that has only
// fired a handful of times (a 100% FP rate over 2 alerts is not yet actionable).
const (
	tuneSuppressFPRate    = 0.80
	tuneSuppressMinTotal  = 10
	tuneDowngradeFPRate   = 0.50
	tuneDowngradeMinTotal = 20
	tuneReviewFPRate      = 0.30
	tuneReviewMinTotal    = 10
)

// RecommendTuning turns per-rule FP statistics into ranked tuning recommendations, most
// impactful first (by FP volume, then FP rate). Rules below every threshold produce no
// recommendation. Pure function — no IO — so it is fully unit-testable and reusable.
func RecommendTuning(stats []RuleStat) []TuningRecommendation {
	recs := make([]TuningRecommendation, 0, len(stats))
	for _, s := range stats {
		if s.RuleName == "" || s.TotalCount <= 0 || s.FPCount <= 0 {
			continue
		}
		rate := s.FPRate
		if rate == 0 {
			rate = float64(s.FPCount) / float64(s.TotalCount)
		}
		action, rationale := classifyTuning(rate, s.TotalCount)
		if action == "" {
			continue
		}
		recs = append(recs, TuningRecommendation{
			RuleName:   s.RuleName,
			FPCount:    s.FPCount,
			TotalCount: s.TotalCount,
			FPRate:     rate,
			Action:     action,
			Rationale:  rationale,
		})
	}
	// Rank by FP volume first (biggest analyst-time sink), then by FP rate.
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].FPCount != recs[j].FPCount {
			return recs[i].FPCount > recs[j].FPCount
		}
		return recs[i].FPRate > recs[j].FPRate
	})
	return recs
}

// classifyTuning picks the action for a rule from its FP rate and volume, most severe
// first. Returns ("","") when no threshold is met.
func classifyTuning(rate float64, total int) (TuningAction, string) {
	switch {
	case rate >= tuneSuppressFPRate && total >= tuneSuppressMinTotal:
		return ActionSuppress, "誤検知率が極めて高く件数も十分。抑制ルールの追加か検知条件の絞り込みを推奨。"
	case rate >= tuneDowngradeFPRate && total >= tuneDowngradeMinTotal:
		return ActionDowngrade, "誤検知が多い。重大度の引き下げ、または対象を限定した例外の追加を推奨。"
	case rate >= tuneReviewFPRate && total >= tuneReviewMinTotal:
		return ActionReview, "誤検知率が上昇傾向。悪化前の内容確認を推奨。"
	}
	return "", ""
}
