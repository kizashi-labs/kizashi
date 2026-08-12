package detectionmetrics

import (
	"context"
	"testing"
)

// ─── NewTracker ───────────────────────────────────────────────────────────────

func TestNewTracker_NotNil(t *testing.T) {
	tr := NewTracker(nil)
	if tr == nil {
		t.Fatal("NewTracker は nil を返すべきではありません")
	}
}

// ─── periodToInterval ─────────────────────────────────────────────────────────

func TestPeriodToInterval_24h(t *testing.T) {
	if got := periodToInterval("24h"); got != "24 hours" {
		t.Errorf("24h: got %q, want '24 hours'", got)
	}
}

func TestPeriodToInterval_7d(t *testing.T) {
	if got := periodToInterval("7d"); got != "7 days" {
		t.Errorf("7d: got %q, want '7 days'", got)
	}
}

func TestPeriodToInterval_30d(t *testing.T) {
	if got := periodToInterval("30d"); got != "30 days" {
		t.Errorf("30d: got %q, want '30 days'", got)
	}
}

func TestPeriodToInterval_Unknown_Defaults7Days(t *testing.T) {
	if got := periodToInterval("unknown"); got != "7 days" {
		t.Errorf("unknown: got %q, want '7 days'", got)
	}
}

func TestPeriodToInterval_EmptyString_Defaults7Days(t *testing.T) {
	if got := periodToInterval(""); got != "7 days" {
		t.Errorf("空文字列: got %q, want '7 days'", got)
	}
}

func TestPeriodToInterval_CaseSensitive(t *testing.T) {
	// "24H" は "24h" とは別扱い → default
	if got := periodToInterval("24H"); got != "7 days" {
		t.Errorf("大文字 24H: got %q, want '7 days' (デフォルト)", got)
	}
}

// ─── Calculate (pool=nil) ─────────────────────────────────────────────────────

func TestCalculate_NilPool_ReturnsNonNil(t *testing.T) {
	tr := NewTracker(nil)
	m, err := tr.Calculate(context.Background(), "24h")
	if err != nil {
		t.Fatalf("Calculate (pool=nil): 予期しないエラー: %v", err)
	}
	if m == nil {
		t.Fatal("Calculate (pool=nil): nil が返されました")
	}
}

func TestCalculate_NilPool_SetsPeriod(t *testing.T) {
	tr := NewTracker(nil)
	m, _ := tr.Calculate(context.Background(), "7d")
	if m.Period != "7d" {
		t.Errorf("Calculate: Period got %q, want 7d", m.Period)
	}
}

func TestCalculate_NilPool_HasInitializedMaps(t *testing.T) {
	tr := NewTracker(nil)
	m, _ := tr.Calculate(context.Background(), "30d")
	if m.MITRECoverage == nil {
		t.Error("MITRECoverage は nil でないはずです")
	}
	if m.SeverityDistribution == nil {
		t.Error("SeverityDistribution は nil でないはずです")
	}
}

func TestCalculate_NilPool_HasInitializedSlices(t *testing.T) {
	tr := NewTracker(nil)
	m, _ := tr.Calculate(context.Background(), "24h")
	if m.TopFalsePositiveRules == nil {
		t.Error("TopFalsePositiveRules は nil でないはずです")
	}
	if m.TrendData == nil {
		t.Error("TrendData は nil でないはずです")
	}
}

func TestCalculate_NilPool_ZeroMetrics(t *testing.T) {
	tr := NewTracker(nil)
	m, _ := tr.Calculate(context.Background(), "24h")
	// pool=nil なのでクエリは実行されずゼロ値のはず
	if m.TotalAlerts != 0 {
		t.Errorf("TotalAlerts (pool=nil): got %d, want 0", m.TotalAlerts)
	}
	if m.FalsePositiveRate != 0 {
		t.Errorf("FalsePositiveRate (pool=nil): got %f, want 0", m.FalsePositiveRate)
	}
}

func TestCalculate_NilPool_AllPeriods(t *testing.T) {
	tr := NewTracker(nil)
	for _, period := range []string{"24h", "7d", "30d"} {
		m, err := tr.Calculate(context.Background(), period)
		if err != nil {
			t.Errorf("Calculate(%q): エラー: %v", period, err)
		}
		if m == nil {
			t.Fatalf("Calculate(%q): nil が返されました", period)
		}
		if m.Period != period {
			t.Errorf("Calculate(%q): Period got %q", period, m.Period)
		}
	}
}
