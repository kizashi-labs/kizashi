package detection

import (
	"testing"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

func TestRansomwareCorrelator_TwoAxesAlertButDoNotIsolate(t *testing.T) {
	r := newRansomwareCorrelator()
	base := time.Unix(1_700_000_000, 0)

	if m := r.Observe("a1", ransomSigDefenseTamper, base); len(m) != 0 {
		t.Fatalf("single axis should not correlate, got %d", len(m))
	}
	m := r.Observe("a1", ransomSigRecoveryInhibit, base.Add(2*time.Minute))
	if len(m) != 1 {
		t.Fatalf("defense-tamper + recovery-inhibit should correlate, got %d", len(m))
	}
	if m[0].Severity != 9 {
		t.Errorf("two-axis composite: want sev 9, got %d", m[0].Severity)
	}
	if m[0].AutoIsolate {
		t.Error("two axes must not drive unattended isolation, even two specific ones")
	}
	if m[0].RuleType != "correlation" {
		t.Errorf("RuleType = %q, want correlation", m[0].RuleType)
	}
}

func TestRansomwareCorrelator_EscalatesOnThirdAxis(t *testing.T) {
	r := newRansomwareCorrelator()
	base := time.Unix(1_700_000_000, 0)
	r.Observe("a1", ransomSigDefenseTamper, base)
	if m := r.Observe("a1", ransomSigRecoveryInhibit, base.Add(time.Minute)); len(m) != 1 {
		t.Fatalf("2nd axis should fire once, got %d", len(m))
	}
	// Re-observing the SAME 2 axes must not re-fire.
	if m := r.Observe("a1", ransomSigRecoveryInhibit, base.Add(2*time.Minute)); len(m) != 0 {
		t.Errorf("re-observing an already-counted axis must not re-fire, got %d", len(m))
	}
	// A third distinct axis grows the set and re-fires, now with isolation armed:
	// three axes including a specific one (defense_tamper / recovery_inhibit).
	m := r.Observe("a1", ransomSigACLStage, base.Add(3*time.Minute))
	if len(m) != 1 {
		t.Fatalf("3rd distinct axis should re-fire on growth, got %d", len(m))
	}
	if m[0].Severity != 10 || !m[0].AutoIsolate {
		t.Errorf("3 axes incl. a specific one: want sev 10 + isolate, got %d / %v", m[0].Severity, m[0].AutoIsolate)
	}
}

func TestRansomwareCorrelator_DifferentHostsDoNotCorrelate(t *testing.T) {
	r := newRansomwareCorrelator()
	base := time.Unix(1_700_000_000, 0)
	r.Observe("a1", ransomSigDefenseTamper, base)
	if m := r.Observe("a2", ransomSigRecoveryInhibit, base.Add(time.Minute)); len(m) != 0 {
		t.Errorf("signals on different hosts must not correlate, got %d", len(m))
	}
}

func TestRansomwareCorrelator_WindowExpiry(t *testing.T) {
	r := newRansomwareCorrelator()
	base := time.Unix(1_700_000_000, 0)
	r.Observe("a1", ransomSigDefenseTamper, base)
	if m := r.Observe("a1", ransomSigRecoveryInhibit, base.Add(ransomWindow+time.Minute)); len(m) != 0 {
		t.Errorf("axes separated by more than the window must not correlate, got %d", len(m))
	}
}

func TestRansomwareCorrelator_UnknownSignalIgnored(t *testing.T) {
	r := newRansomwareCorrelator()
	base := time.Unix(1_700_000_000, 0)
	if m := r.Observe("a1", "not-a-real-signal", base); len(m) != 0 {
		t.Errorf("unknown signal class must be ignored, got %d", len(m))
	}
	if m := r.Observe("", ransomSigDefenseTamper, base); len(m) != 0 {
		t.Errorf("empty agentID must be ignored, got %d", len(m))
	}
}

func TestClassifyRansomwareSignal(t *testing.T) {
	cases := []struct {
		m    *detectionrules.RuleMatch
		want string
	}{
		{&detectionrules.RuleMatch{MITRETags: []string{"T1490"}, RuleName: "Volume Shadow Copy Deletion"}, ransomSigRecoveryInhibit},
		{&detectionrules.RuleMatch{MITRETags: []string{"T1489"}, RuleName: "Security or Backup Service Tampering"}, ransomSigDefenseTamper},
		{&detectionrules.RuleMatch{MITRETags: []string{"T1222.001"}, RuleName: "Broad File Permission Change via icacls/takeown"}, ransomSigACLStage},
		{&detectionrules.RuleMatch{MITRETags: []string{"T1046"}, RuleName: "port scan"}, ""},
		{nil, ""},
	}
	for i, tc := range cases {
		if got := classifyRansomwareSignal(tc.m); got != tc.want {
			t.Errorf("case %d: classifyRansomwareSignal = %q, want %q", i, got, tc.want)
		}
	}
}
