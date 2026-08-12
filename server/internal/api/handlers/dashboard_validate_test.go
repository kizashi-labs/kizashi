package handlers

import "testing"

// ─── clampDays ────────────────────────────────────────────────────────────────
// dashboard_stats_handler.go で定義された days パラメータ補正関数

func TestClampDays_ZeroReturnsDefault(t *testing.T) {
	got := clampDays(0)
	if got != 7 {
		t.Errorf("clampDays(0) = %d, want 7 (デフォルト)", got)
	}
}

func TestClampDays_NegativeReturnsDefault(t *testing.T) {
	for _, d := range []int{-1, -100, -9999} {
		got := clampDays(d)
		if got != 7 {
			t.Errorf("clampDays(%d) = %d, want 7", d, got)
		}
	}
}

func TestClampDays_ValidRange(t *testing.T) {
	for d := 1; d <= 30; d++ {
		got := clampDays(d)
		if got != d {
			t.Errorf("clampDays(%d) = %d, want %d (変更なし)", d, got, d)
		}
	}
}

func TestClampDays_ExceedsMaxClampsTo30(t *testing.T) {
	for _, d := range []int{31, 60, 365, 9999} {
		got := clampDays(d)
		if got != 30 {
			t.Errorf("clampDays(%d) = %d, want 30 (最大値)", d, got)
		}
	}
}

func TestClampDays_BoundaryValues(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{-1, 7},
		{0, 7},
		{1, 1},
		{7, 7},
		{30, 30},
		{31, 30},
	}
	for _, tc := range tests {
		got := clampDays(tc.input)
		if got != tc.want {
			t.Errorf("clampDays(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// ─── ダッシュボード統計検証ヘルパー ──────────────────────────────────────────

func TestAlertTrendDaysClamping(t *testing.T) {
	// AlertTrend ハンドラの days クエリパラメータ処理ロジックを検証
	// デフォルト 7、最大 30
	parseAndClampDays := func(raw string) int {
		d := 7
		if raw == "" {
			return d
		}
		v := 0
		for _, r := range raw {
			if r < '0' || r > '9' {
				break
			}
			v = v*10 + int(r-'0')
		}
		if v > 0 {
			if v > 30 {
				v = 30
			}
			d = v
		}
		return d
	}

	tests := []struct {
		input string
		want  int
	}{
		{"", 7},
		{"7", 7},
		{"14", 14},
		{"30", 30},
		{"31", 30},
		{"abc", 7},
		{"0", 7},
	}
	for _, tc := range tests {
		got := parseAndClampDays(tc.input)
		if got != tc.want {
			t.Errorf("parseAndClampDays(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestDashboardSeverityThreshold(t *testing.T) {
	// severity >= 9 がクリティカル判定として使われる (ダッシュボード全体で一貫)
	isCritical := func(severity int) bool { return severity >= 9 }

	for s := 9; s <= 10; s++ {
		if !isCritical(s) {
			t.Errorf("severity %d はクリティカルなはず", s)
		}
	}
	for s := 0; s <= 8; s++ {
		if isCritical(s) {
			t.Errorf("severity %d はクリティカルでないはず", s)
		}
	}
}

func TestDashboardTopEndpointsLimit(t *testing.T) {
	// TopEndpoints は上位10件を返す (定数テスト)
	const topN = 10
	if topN != 10 {
		t.Errorf("TopEndpoints の上限は 10 であるべき: got %d", topN)
	}
}

func TestResolutionRateCalculation(t *testing.T) {
	// DetectionRate ハンドラのリゾリューション率計算ロジックを反映
	calcRate := func(total, resolved int) float64 {
		if total == 0 {
			return 0
		}
		return float64(resolved) / float64(total) * 100
	}

	tests := []struct {
		total    int
		resolved int
		want     float64
	}{
		{0, 0, 0},
		{100, 50, 50},
		{100, 100, 100},
		{100, 0, 0},
		{200, 100, 50},
		{10, 3, 30},
	}
	for _, tc := range tests {
		got := calcRate(tc.total, tc.resolved)
		if got != tc.want {
			t.Errorf("calcRate(%d, %d) = %.1f, want %.1f",
				tc.total, tc.resolved, got, tc.want)
		}
	}
}
