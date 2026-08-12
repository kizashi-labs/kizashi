package detection

import (
	"math"
	"testing"
)

const floatEps = 1e-9

func feed(d *StatAnomalyDetector, userKey, metric string, values ...float64) {
	for _, v := range values {
		d.UpdateBaseline(userKey, metric, v)
	}
}

// TestStatAnomaly_WelfordBaseline checks running mean/stddev/min/max via the
// classic [2,4,6] dataset (mean=4, sample stddev=2).
func TestStatAnomaly_WelfordBaseline(t *testing.T) {
	d := NewStatAnomalyDetector()
	feed(d, "u1", "cpu", 2, 4, 6)

	// CheckAnomaly exposes the current mean as Baseline; verify it.
	res := d.CheckAnomaly("u1", "cpu", 4)
	if math.Abs(res.Baseline-4.0) > floatEps {
		t.Errorf("mean: got %v, want 4.0", res.Baseline)
	}
	// value == mean → z 0 → not anomalous
	if res.IsAnomaly || math.Abs(res.ZScore) > floatEps {
		t.Errorf("value at mean should not be anomalous: %+v", res)
	}
}

func TestStatAnomaly_ZScoreThresholds(t *testing.T) {
	// baseline [2,4,6] → mean=4, stddev=2
	cases := []struct {
		value     float64
		wantZ     float64
		wantAnom  bool
		wantSever string
	}{
		{4, 0, false, "low"},
		{8, 2.0, true, "medium"}, // (8-4)/2
		{10, 3.0, true, "high"},  // (10-4)/2
		{12, 4.0, true, "critical"},
		{-4, -4.0, true, "critical"}, // negative direction, |z|=4
	}
	for _, tc := range cases {
		d := NewStatAnomalyDetector()
		feed(d, "u", "m", 2, 4, 6)
		res := d.CheckAnomaly("u", "m", tc.value)
		if math.Abs(res.ZScore-tc.wantZ) > 1e-9 {
			t.Errorf("value %v: ZScore got %v, want %v", tc.value, res.ZScore, tc.wantZ)
		}
		if res.IsAnomaly != tc.wantAnom {
			t.Errorf("value %v: IsAnomaly got %v, want %v", tc.value, res.IsAnomaly, tc.wantAnom)
		}
		if res.Severity != tc.wantSever {
			t.Errorf("value %v: Severity got %q, want %q", tc.value, res.Severity, tc.wantSever)
		}
	}
}

func TestStatAnomaly_InsufficientSamples(t *testing.T) {
	d := NewStatAnomalyDetector()
	feed(d, "u", "m", 100, 100) // only 2 samples (< 3)
	res := d.CheckAnomaly("u", "m", 9999)
	if res.IsAnomaly {
		t.Error("with < 3 samples no anomaly should be reported")
	}
	if res.ZScore != 0 || res.Baseline != 0 {
		t.Errorf("insufficient-sample result should be zero-valued: %+v", res)
	}
}

func TestStatAnomaly_UnknownKey(t *testing.T) {
	d := NewStatAnomalyDetector()
	res := d.CheckAnomaly("nobody", "nothing", 42)
	if res.IsAnomaly {
		t.Error("unknown baseline must not be anomalous")
	}
	if res.MetricName != "nothing" || res.Actual != 42 {
		t.Errorf("result metadata should still be populated: %+v", res)
	}
}

// TestStatAnomaly_ZeroVariance documents the behaviour when all samples are
// identical: a higher value is capped at z=5 (critical), an equal or LOWER
// value is not flagged.
func TestStatAnomaly_ZeroVariance(t *testing.T) {
	d := NewStatAnomalyDetector()
	feed(d, "u", "m", 5, 5, 5) // stddev 0

	high := d.CheckAnomaly("u", "m", 6)
	if !high.IsAnomaly || high.Severity != "critical" || high.ZScore != 5.0 {
		t.Errorf("higher value over zero-variance baseline should be critical z=5: %+v", high)
	}
	eq := d.CheckAnomaly("u", "m", 5)
	if eq.IsAnomaly {
		t.Errorf("equal value should not be anomalous: %+v", eq)
	}
	low := d.CheckAnomaly("u", "m", 4)
	if low.IsAnomaly {
		t.Errorf("lower value over zero-variance baseline is not flagged (documented quirk): %+v", low)
	}
}

// TestStatAnomaly_KeysAreIsolated ensures user+metric baselines don't leak.
func TestStatAnomaly_KeysAreIsolated(t *testing.T) {
	d := NewStatAnomalyDetector()
	feed(d, "u1", "cpu", 2, 4, 6)       // mean 4
	feed(d, "u2", "cpu", 100, 100, 100) // mean 100
	feed(d, "u1", "mem", 0, 0, 0)       // mean 0

	if r := d.CheckAnomaly("u1", "cpu", 4); math.Abs(r.Baseline-4) > floatEps {
		t.Errorf("u1/cpu baseline leaked: %+v", r)
	}
	if r := d.CheckAnomaly("u2", "cpu", 100); math.Abs(r.Baseline-100) > floatEps {
		t.Errorf("u2/cpu baseline leaked: %+v", r)
	}
	// u1/cpu value 100 should be wildly anomalous, proving it did not absorb u2's data.
	if r := d.CheckAnomaly("u1", "cpu", 100); !r.IsAnomaly {
		t.Errorf("u1/cpu should flag 100 as anomalous: %+v", r)
	}
}

func TestStatAnomaly_BaselineKey(t *testing.T) {
	if got := baselineKey("alice", "logins"); got != "alice:logins" {
		t.Errorf("baselineKey: got %q, want alice:logins", got)
	}
}

// TestAnomalyDetector_CalcZScore covers the DB-backed detector's pure z-score helper.
func TestAnomalyDetector_CalcZScore(t *testing.T) {
	d := &AnomalyDetector{}
	if z := d.calcZScore(10, 4, 2); math.Abs(z-3.0) > floatEps {
		t.Errorf("(10-4)/2 should be 3.0, got %v", z)
	}
	if z := d.calcZScore(0, 4, 2); math.Abs(z-(-2.0)) > floatEps {
		t.Errorf("(0-4)/2 should be -2.0, got %v", z)
	}
	// Zero stddev, higher value → flagged above the threshold.
	if z := d.calcZScore(9, 5, 0); z <= zScoreThreshold {
		t.Errorf("zero-variance higher value should exceed threshold, got %v", z)
	}
	// Zero stddev, equal/lower value → 0.
	if z := d.calcZScore(5, 5, 0); z != 0 {
		t.Errorf("zero-variance equal value should be 0, got %v", z)
	}
	if z := d.calcZScore(3, 5, 0); z != 0 {
		t.Errorf("zero-variance lower value should be 0, got %v", z)
	}
}
