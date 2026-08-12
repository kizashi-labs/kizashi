package detection

import (
	"testing"
	"time"
)

// TestRuntimeDetectorsFeedKillChain verifies the new runtime burst detectors emit
// techniques whose tactics the KillChainScorer recognizes, so their matches
// (which the engine appends to the per-event match set) contribute distinct
// kill-chain stages. It asserts the tactic mapping and that four such stages
// correlate into one alert.
func TestRuntimeDetectorsFeedKillChain(t *testing.T) {
	want := map[string]string{
		"T1110":     "credential-access", // brute force
		"T1110.003": "credential-access", // password spray (sub inherits base)
		"T1486":     "impact",            // ransomware burst
		"T1021":     "lateral-movement",  // lateral fan-out
	}
	for tech, tac := range want {
		if got := tacticForTechnique(tech); got != tac {
			t.Errorf("tacticForTechnique(%q) = %q, want %q", tech, got, tac)
		}
	}

	// A realistic intrusion touching four distinct tactics via the new detectors'
	// techniques plus a discovery stage → one correlated kill-chain alert.
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	seq := [][]string{
		{"T1110"}, // credential-access (brute force)
		{"T1021"}, // lateral-movement (lateral fan-out)
		{"T1486"}, // impact (ransomware burst)
		{"T1082"}, // discovery
	}
	var fired int
	for i, tags := range seq {
		fired += len(k.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute)))
	}
	if fired != 1 {
		t.Fatalf("four distinct tactics from runtime detectors should correlate into 1 kill-chain alert, got %d", fired)
	}
}
