package siem

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// alertWithSeverity builds a minimal AlertPayload carrying the given platform
// severity (1-10 scale). Helpers are intentionally not shared with
// forwarder_test.go so this file compiles regardless of merge order.
func alertWithSeverity(sev int) *AlertPayload {
	return &AlertPayload{
		ID:        "sevtest-0001",
		AgentID:   "agent-1",
		Hostname:  "WIN-01",
		OS:        "windows",
		RuleName:  "Severity Mapping Probe",
		Severity:  sev,
		Status:    "open",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

// TestCEFSeverityMapping guards against the 1-10 → CEF regression: a critical
// sev-9 alert must surface as CEF severity 9, not 0 (the old alert.Severity/10
// integer-division bug mapped every real alert to ~0, the lowest priority).
func TestCEFSeverityMapping(t *testing.T) {
	cases := []struct {
		sev  int
		want int
	}{
		{1, 1},
		{5, 5},
		{9, 9},   // AUTO_ISOLATE_MIN_SEVERITY — the crux of the bug
		{10, 10}, // top of the alert scale
		{0, 0},
		{-1, 0},  // defensive lower clamp
		{50, 10}, // defensive upper clamp
	}
	for _, tc := range cases {
		if got := cefSeverity(tc.sev); got != tc.want {
			t.Errorf("cefSeverity(%d) = %d, want %d", tc.sev, got, tc.want)
		}

		want := fmt.Sprintf("|%d|", tc.want)
		if out := formatCEF(alertWithSeverity(tc.sev)); !strings.Contains(out, want) {
			t.Errorf("formatCEF sev=%d: missing %q in %q", tc.sev, want, out)
		}

		wantLEEF := fmt.Sprintf("sev=%d\t", tc.want)
		if out := formatLEEF(alertWithSeverity(tc.sev)); !strings.Contains(out, wantLEEF) {
			t.Errorf("formatLEEF sev=%d: missing %q in %q", tc.sev, wantLEEF, out)
		}
	}
}
