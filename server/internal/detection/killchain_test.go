package detection

import (
	"testing"
	"time"
)

func TestKillChainScorer_FiresOnMultiStage(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// Feed a realistic intrusion: discovery, execution, credential-access,
	// exfiltration — 4 distinct tactics within the window.
	seq := [][]string{
		{"T1082"},     // discovery
		{"T1059.004"}, // execution
		{"T1003"},     // credential-access
		{"T1048"},     // exfiltration
	}
	var fired int
	for i, tags := range seq {
		m := k.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute))
		fired += len(m)
		if len(m) > 0 && m[0].RuleType != "correlation" {
			t.Errorf("expected correlation match, got %q", m[0].RuleType)
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 kill-chain alert after 4 tactics, got %d", fired)
	}
}

func TestKillChainScorer_NoFireBelowThreshold(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// Only 3 distinct tactics — below chainMinTactics(4).
	for i, tags := range [][]string{{"T1082"}, {"T1057"}, {"T1059"}} {
		if m := k.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("fired with only %d tactics", i+1)
		}
	}
}

func TestKillChainScorer_SameTacticRepeatedNoFire(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// Many discovery techniques but all one tactic — not a chain.
	for i, tags := range [][]string{{"T1082"}, {"T1057"}, {"T1016"}, {"T1083"}, {"T1087"}} {
		if m := k.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("fired on single-tactic (discovery) burst at step %d", i)
		}
	}
}

func TestKillChainScorer_WindowExpiry(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	tactics := [][]string{{"T1082"}, {"T1059"}, {"T1003"}, {"T1048"}}
	for i, tags := range tactics {
		// Each event > window apart → tactics never co-occur.
		at := base.Add(time.Duration(i) * 2 * chainWindow)
		if m := k.Observe("agent1", tags, at); len(m) > 0 {
			t.Fatalf("fired on tactics spread beyond the window")
		}
	}
}

func TestKillChainScorer_SeverityScales(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	tactics := []string{"T1082", "T1059", "T1003", "T1048", "T1071", "T1486"} // 6 tactics
	var got *int
	for i, tag := range tactics {
		m := k.Observe("agent-sev", []string{tag}, base.Add(time.Duration(i)*time.Second))
		if len(m) > 0 {
			s := m[0].Severity
			got = &s
		}
	}
	if got == nil {
		t.Fatal("expected a kill-chain alert")
	}
	if *got != 9 {
		t.Errorf("expected severity 9 for a 6-tactic chain, got %d", *got)
	}
}

func TestTacticForTechnique(t *testing.T) {
	cases := map[string]string{
		"T1003":     "credential-access",
		"T1059.004": "execution",
		"T1046":     "discovery",
		"T1048":     "exfiltration",
		"T1486":     "impact",
		"T9999":     "",
	}
	for tech, want := range cases {
		if got := tacticForTechnique(tech); got != want {
			t.Errorf("tacticForTechnique(%q) = %q, want %q", tech, got, want)
		}
	}
}

// TestTacticForTechnique_ExpandedCoverage verifies techniques added to the
// kill-chain tactic map (⑤ correlation拡充) classify into the correct tactic, so
// they contribute to multi-stage correlation instead of being ignored.
func TestTacticForTechnique_ExpandedCoverage(t *testing.T) {
	cases := map[string]string{
		"T1496":     "impact",               // resource hijacking (cryptomining)
		"T1040":     "credential-access",    // network sniffing
		"T1014":     "defense-evasion",      // rootkit
		"T1123":     "collection",           // audio capture
		"T1125":     "collection",           // video capture
		"T1572":     "command-and-control",  // protocol tunneling
		"T1611":     "privilege-escalation", // escape to host
		"T1548.001": "privilege-escalation", // sub-technique inherits base
		"T1046":     "discovery",
		"T1552.003": "credential-access",
	}
	for tech, want := range cases {
		if got := tacticForTechnique(tech); got != want {
			t.Errorf("tacticForTechnique(%q) = %q, want %q", tech, got, want)
		}
	}
}

// TestKillChainScorer_NewlyMappedTechniquesCorrelate proves that an intrusion
// built from techniques that were previously UNMAPPED (and thus invisible to the
// kill-chain aggregator) now crosses the 4-distinct-tactic threshold and fires.
func TestKillChainScorer_NewlyMappedTechniquesCorrelate(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// audio capture (collection) → network sniffing (credential-access) →
	// protocol tunneling (C2) → resource hijacking (impact): 4 tactics, all from
	// techniques added in the ⑤ expansion.
	seq := [][]string{
		{"T1123"}, // collection
		{"T1040"}, // credential-access
		{"T1572"}, // command-and-control
		{"T1496"}, // impact
	}
	var fired int
	for i, tags := range seq {
		fired += len(k.Observe("agentX", tags, base.Add(time.Duration(i)*time.Minute)))
	}
	if fired != 1 {
		t.Fatalf("newly-mapped 4-tactic chain should fire exactly 1 alert, got %d", fired)
	}
}
