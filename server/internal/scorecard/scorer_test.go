package scorecard

import (
	"strings"
	"testing"
)

// ─── NewScorer ────────────────────────────────────────────────────────────────

func TestNewScorer_NotNil(t *testing.T) {
	s := NewScorer(nil)
	if s == nil {
		t.Fatal("NewScorer は nil を返すべきではありません")
	}
}

// ─── statusFromScore ──────────────────────────────────────────────────────────

func TestStatusFromScore_80_IsCompliant(t *testing.T) {
	if got := statusFromScore(80); got != "compliant" {
		t.Errorf("statusFromScore(80): got %q, want compliant", got)
	}
}

func TestStatusFromScore_100_IsCompliant(t *testing.T) {
	if got := statusFromScore(100); got != "compliant" {
		t.Errorf("statusFromScore(100): got %q, want compliant", got)
	}
}

func TestStatusFromScore_79_IsPartial(t *testing.T) {
	if got := statusFromScore(79); got != "partial" {
		t.Errorf("statusFromScore(79): got %q, want partial", got)
	}
}

func TestStatusFromScore_50_IsPartial(t *testing.T) {
	if got := statusFromScore(50); got != "partial" {
		t.Errorf("statusFromScore(50): got %q, want partial", got)
	}
}

func TestStatusFromScore_49_IsNonCompliant(t *testing.T) {
	if got := statusFromScore(49); got != "non_compliant" {
		t.Errorf("statusFromScore(49): got %q, want non_compliant", got)
	}
}

func TestStatusFromScore_0_IsNonCompliant(t *testing.T) {
	if got := statusFromScore(0); got != "non_compliant" {
		t.Errorf("statusFromScore(0): got %q, want non_compliant", got)
	}
}

// ─── minFloat ─────────────────────────────────────────────────────────────────

func TestMinFloat_ASmaller(t *testing.T) {
	if got := minFloat(1.5, 3.0); got != 1.5 {
		t.Errorf("minFloat(1.5, 3.0): got %f, want 1.5", got)
	}
}

func TestMinFloat_BSmaller(t *testing.T) {
	if got := minFloat(5.0, 2.5); got != 2.5 {
		t.Errorf("minFloat(5.0, 2.5): got %f, want 2.5", got)
	}
}

func TestMinFloat_Equal(t *testing.T) {
	if got := minFloat(4.0, 4.0); got != 4.0 {
		t.Errorf("minFloat(4.0, 4.0): got %f, want 4.0", got)
	}
}

// ─── floatIf ──────────────────────────────────────────────────────────────────

func TestFloatIf_TrueReturnsT(t *testing.T) {
	if got := floatIf(true, 10.0, 5.0); got != 10.0 {
		t.Errorf("floatIf(true, 10, 5): got %f, want 10.0", got)
	}
}

func TestFloatIf_FalseReturnsF(t *testing.T) {
	if got := floatIf(false, 10.0, 5.0); got != 5.0 {
		t.Errorf("floatIf(false, 10, 5): got %f, want 5.0", got)
	}
}

func TestFloatIf_ZeroValues(t *testing.T) {
	if got := floatIf(true, 0.0, 100.0); got != 0.0 {
		t.Errorf("floatIf(true, 0, 100): got %f, want 0.0", got)
	}
}

// ─── GetRecommendations ───────────────────────────────────────────────────────

func TestGetRecommendations_AllCompliant_ReturnsDefaultMsg(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		Controls: []*Control{
			{Name: "A", Status: "compliant", Score: 90},
			{Name: "B", Status: "compliant", Score: 85},
		},
	}
	recs := s.GetRecommendations(sc)
	if len(recs) != 1 {
		t.Fatalf("全 compliant: got %d recommendations, want 1", len(recs))
	}
	if !strings.Contains(recs[0], "compliant") {
		t.Errorf("全 compliant: メッセージに 'compliant' が含まれていません: %q", recs[0])
	}
}

func TestGetRecommendations_NonCompliant_IncludesName(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		Controls: []*Control{
			{Name: "Weak Control", Status: "non_compliant", Score: 20, Category: "Protect"},
		},
	}
	recs := s.GetRecommendations(sc)
	if len(recs) == 0 {
		t.Fatal("non_compliant コントロールがあれば推奨事項が返るべきです")
	}
	if !strings.Contains(recs[0], "Weak Control") {
		t.Errorf("推奨事項にコントロール名が含まれていません: %q", recs[0])
	}
}

func TestGetRecommendations_MaxFive(t *testing.T) {
	s := NewScorer(nil)
	controls := make([]*Control, 10)
	for i := range controls {
		controls[i] = &Control{Name: "Ctrl", Status: "partial", Score: 40, Category: "Detect"}
	}
	sc := &Scorecard{Controls: controls}
	recs := s.GetRecommendations(sc)
	if len(recs) > 5 {
		t.Errorf("GetRecommendations: got %d, want <= 5", len(recs))
	}
}

func TestGetRecommendations_EmptyControls_ReturnsDefaultMsg(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{Controls: []*Control{}}
	recs := s.GetRecommendations(sc)
	if len(recs) != 1 {
		t.Fatalf("空コントロール: got %d recommendations, want 1", len(recs))
	}
}

func TestGetRecommendations_SortedByScore(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		Controls: []*Control{
			{Name: "Medium", Status: "partial", Score: 50, Category: "Detect"},
			{Name: "Lowest", Status: "non_compliant", Score: 10, Category: "Protect"},
			{Name: "Low", Status: "partial", Score: 30, Category: "Identify"},
		},
	}
	recs := s.GetRecommendations(sc)
	// 最低スコア "Lowest" が先頭に来るべき
	if !strings.Contains(recs[0], "Lowest") {
		t.Errorf("最低スコアが先頭でない: %q", recs[0])
	}
}

// ─── calculateScores ──────────────────────────────────────────────────────────

func TestCalculateScores_SingleControl_OverallEqualsScore(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: make(map[string]float64),
		Controls: []*Control{
			{Category: "Protect", Score: 70, Weight: 1.0},
		},
	}
	s.calculateScores(sc)
	if sc.OverallScore != 70.0 {
		t.Errorf("OverallScore: got %f, want 70.0", sc.OverallScore)
	}
	if sc.CategoryScores["Protect"] != 70.0 {
		t.Errorf("CategoryScores[Protect]: got %f, want 70.0", sc.CategoryScores["Protect"])
	}
}

func TestCalculateScores_WeightedAverage(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: make(map[string]float64),
		Controls: []*Control{
			{Category: "Cat", Score: 100, Weight: 1.0},
			{Category: "Cat", Score: 0, Weight: 1.0},
		},
	}
	s.calculateScores(sc)
	if sc.OverallScore != 50.0 {
		t.Errorf("OverallScore (average): got %f, want 50.0", sc.OverallScore)
	}
}

func TestCalculateScores_EmptyControls_OverallZero(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: make(map[string]float64),
		Controls:       []*Control{},
	}
	s.calculateScores(sc)
	if sc.OverallScore != 0 {
		t.Errorf("空コントロール: OverallScore got %f, want 0", sc.OverallScore)
	}
}

func TestCalculateScores_MultipleCategoriesWeighted(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: make(map[string]float64),
		Controls: []*Control{
			{Category: "A", Score: 80, Weight: 2.0},
			{Category: "B", Score: 20, Weight: 2.0},
		},
	}
	s.calculateScores(sc)
	// A: 80, B: 20 → weighted average = (80*2 + 20*2) / (2+2) = 50
	if sc.OverallScore != 50.0 {
		t.Errorf("多カテゴリ重み付き: OverallScore got %f, want 50.0", sc.OverallScore)
	}
}
