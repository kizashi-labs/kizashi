package handlers

import "testing"

// ─── scoreToRiskLevel ─────────────────────────────────────────────────────────

func TestScoreToRiskLevel_Critical(t *testing.T) {
	cases := []float64{80, 85, 99, 100}
	for _, score := range cases {
		got := scoreToRiskLevel(score)
		if got != "critical" {
			t.Errorf("scoreToRiskLevel(%.0f) = %q, want \"critical\"", score, got)
		}
	}
}

func TestScoreToRiskLevel_High(t *testing.T) {
	cases := []float64{60, 65, 79, 79.9}
	for _, score := range cases {
		got := scoreToRiskLevel(score)
		if got != "high" {
			t.Errorf("scoreToRiskLevel(%.1f) = %q, want \"high\"", score, got)
		}
	}
}

func TestScoreToRiskLevel_Medium(t *testing.T) {
	cases := []float64{30, 45, 59, 59.9}
	for _, score := range cases {
		got := scoreToRiskLevel(score)
		if got != "medium" {
			t.Errorf("scoreToRiskLevel(%.1f) = %q, want \"medium\"", score, got)
		}
	}
}

func TestScoreToRiskLevel_Low(t *testing.T) {
	cases := []float64{0, 1, 15, 29, 29.9}
	for _, score := range cases {
		got := scoreToRiskLevel(score)
		if got != "low" {
			t.Errorf("scoreToRiskLevel(%.1f) = %q, want \"low\"", score, got)
		}
	}
}

func TestScoreToRiskLevel_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, "low"},
		{29.99, "low"},
		{30, "medium"},
		{59.99, "medium"},
		{60, "high"},
		{79.99, "high"},
		{80, "critical"},
		{100, "critical"},
	}
	for _, tc := range tests {
		got := scoreToRiskLevel(tc.score)
		if got != tc.want {
			t.Errorf("scoreToRiskLevel(%.2f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestScoreToRiskLevel_NegativeScore(t *testing.T) {
	// 負のスコアは low を返す (DBからの異常値への耐性)
	got := scoreToRiskLevel(-1)
	if got != "low" {
		t.Errorf("scoreToRiskLevel(-1) = %q, want \"low\"", got)
	}
}

func TestScoreToRiskLevel_AllLevelsDistinct(t *testing.T) {
	levels := map[string]bool{}
	for _, score := range []float64{0, 30, 60, 80} {
		levels[scoreToRiskLevel(score)] = true
	}
	if len(levels) != 4 {
		t.Errorf("4つの代表スコアが4つの異なるレベルを返すべき: got %v", levels)
	}
}

// ─── リスクアクション検証ヘルパー (インライン純粋関数テスト) ──────────────────

func TestRiskActionPriority_Valid(t *testing.T) {
	validPriorities := func(p string) bool {
		switch p {
		case "low", "medium", "high", "critical":
			return true
		}
		return false
	}

	for _, p := range []string{"low", "medium", "high", "critical"} {
		if !validPriorities(p) {
			t.Errorf("優先度 %q は有効なはず", p)
		}
	}
}

func TestRiskActionPriority_Invalid(t *testing.T) {
	validPriorities := func(p string) bool {
		switch p {
		case "low", "medium", "high", "critical":
			return true
		}
		return false
	}

	for _, p := range []string{"", "unknown", "urgent", "CRITICAL", "HIGH"} {
		if validPriorities(p) {
			t.Errorf("優先度 %q は無効なはず", p)
		}
	}
}

func TestRiskEntityType_Normalization(t *testing.T) {
	// リスクスコアのエンティティタイプ正規化
	normalizeEntityType := func(t string) string {
		switch t {
		case "agent", "user", "network", "application":
			return t
		default:
			return ""
		}
	}

	tests := []struct {
		input string
		want  string
	}{
		{"agent", "agent"},
		{"user", "user"},
		{"network", "network"},
		{"application", "application"},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := normalizeEntityType(tc.input)
		if got != tc.want {
			t.Errorf("normalizeEntityType(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
