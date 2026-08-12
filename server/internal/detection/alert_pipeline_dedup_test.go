package detection

import (
	"testing"
	"time"
)

// AlertPipeline.isDuplicate is the sliding-window dedup that stops one ongoing
// condition (a discovery flood, a process-spawn burst) from emitting a duplicate
// alert on every event. It had no test (there was no alert_pipeline_test.go), so
// a regression that broke suppression — realert storms — or over-suppressed
// (missing a genuinely new alert) would go unnoticed. These lock its contract.

func TestAlertPipeline_IsDuplicate_SuppressesWithinWindow(t *testing.T) {
	p := NewAlertPipeline(nil, nil)
	const window = time.Minute

	// First sighting of a key is NOT a duplicate (must alert).
	if p.isDuplicate("agent-1|T1059", window) {
		t.Fatalf("first occurrence of a key must not be treated as duplicate")
	}
	// Immediate re-sighting within the window IS a duplicate (suppress).
	if !p.isDuplicate("agent-1|T1059", window) {
		t.Fatalf("second occurrence within the window must be suppressed as duplicate")
	}
	// A different key is independent — never suppressed by another key's sighting.
	if p.isDuplicate("agent-1|T1003", window) {
		t.Fatalf("a distinct key must not be suppressed by another key")
	}
	if p.isDuplicate("agent-2|T1059", window) {
		t.Fatalf("same technique on a different agent is a distinct key, must not be suppressed")
	}
}

func TestAlertPipeline_IsDuplicate_ReAlertsAfterWindow(t *testing.T) {
	p := NewAlertPipeline(nil, nil)

	// A zero-length window means every sighting is outside the previous one's
	// window, so the same key must always be allowed to re-alert (the escape hatch
	// that a too-short window never permanently silences a recurring real attack).
	if p.isDuplicate("k", 0) {
		t.Fatalf("first call must not be duplicate")
	}
	if p.isDuplicate("k", 0) {
		t.Fatalf("with a zero window, a subsequent sighting must re-alert, not be suppressed")
	}
}

// TestCorrelationEngine_ConfigValidation locks the detection.CorrelationEngine
// config guard (distinct from internal/correlation): an invalid threshold or
// window must fall back to safe defaults rather than disabling correlation
// (threshold < 1) or looking back zero time (window <= 0).
func TestCorrelationEngine_ConfigValidation(t *testing.T) {
	ce := NewCorrelationEngineWithConfig(nil, nil, 0, 0)
	if ce.threshold != 3 || ce.window != time.Hour {
		t.Errorf("invalid config should default to threshold=3 window=1h, got threshold=%d window=%s", ce.threshold, ce.window)
	}
	neg := NewCorrelationEngineWithConfig(nil, nil, -1, -time.Second)
	if neg.threshold != 3 || neg.window != time.Hour {
		t.Errorf("negative config should default, got threshold=%d window=%s", neg.threshold, neg.window)
	}
	ok := NewCorrelationEngineWithConfig(nil, nil, 5, 30*time.Minute)
	if ok.threshold != 5 || ok.window != 30*time.Minute {
		t.Errorf("valid config must be preserved, got threshold=%d window=%s", ok.threshold, ok.window)
	}
}
