package zerotrust

import (
	"testing"
)

func TestScoreToLevel(t *testing.T) {
	cases := []struct {
		score int
		want  TrustLevel
	}{
		{90, TrustLevelHigh},
		{80, TrustLevelHigh},
		{79, TrustLevelMedium},
		{50, TrustLevelMedium},
		{49, TrustLevelLow},
		{20, TrustLevelLow},
		{19, TrustLevelUntrusted},
		{0, TrustLevelUntrusted},
	}
	for _, tc := range cases {
		got := scoreToLevel(tc.score)
		if got != tc.want {
			t.Errorf("scoreToLevel(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestCalculateScore(t *testing.T) {
	e := NewEngine(nil)

	// Perfect posture
	p := &DevicePosture{
		AgentHealthy:    true,
		OSPatched:       true,
		DiskEncrypted:   true,
		FirewallEnabled: true,
		AVEnabled:       true,
		MFAEnabled:      true,
		NoActiveAlerts:  true,
		OnCorpNetwork:   true,
	}
	score := e.calculateScore(p)
	if score != 100 {
		t.Errorf("expected perfect score 100, got %d", score)
	}

	// With alerts penalty
	p2 := &DevicePosture{
		AgentHealthy:     true,
		ActiveAlertCount: 3,
		NoActiveAlerts:   false,
	}
	score2 := e.calculateScore(p2)
	expected := 0 // agentHealthy(15) - 3 alerts * penaltyPerAlert(5) = 0
	if score2 != expected {
		t.Errorf("expected score %d, got %d", expected, score2)
	}
}

func TestCheckAccessUnevaluated(t *testing.T) {
	e := NewEngine(nil)
	decision := e.CheckAccess("unknown-agent", "admin")
	if decision.Allowed {
		t.Error("unevaluated device should not be allowed")
	}
	if decision.TrustLevel != TrustLevelUntrusted {
		t.Errorf("expected untrusted, got %s", decision.TrustLevel)
	}
}

func TestUpdatePolicy(t *testing.T) {
	e := NewEngine(nil)
	initialCount := len(e.GetPolicies())

	e.UpdatePolicy(ZeroTrustPolicy{
		ID: "test-policy", Name: "Test", Resource: "test",
		MinTrust: TrustLevelMedium, Enabled: true,
	})

	if len(e.GetPolicies()) != initialCount+1 {
		t.Error("policy count should increase by 1")
	}

	// Update existing
	e.UpdatePolicy(ZeroTrustPolicy{
		ID: "test-policy", Name: "Updated", Resource: "test",
		MinTrust: TrustLevelHigh, Enabled: false,
	})

	if len(e.GetPolicies()) != initialCount+1 {
		t.Error("policy count should not change on update")
	}
}
