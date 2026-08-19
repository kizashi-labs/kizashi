package detection

import (
	"testing"
	"time"
)

func TestKillChainScorer_FiresOnMultiStage(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// Feed a realistic intrusion: discovery, execution, credential-access,
	// lateral-movement, exfiltration — chainMinTactics(5) distinct tactics within
	// the window.
	seq := [][]string{
		{"T1082"},     // discovery
		{"T1059.004"}, // execution
		{"T1003"},     // credential-access
		{"T1021"},     // lateral-movement
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
		t.Fatalf("expected exactly 1 kill-chain alert after 5 tactics, got %d", fired)
	}
}

func TestKillChainScorer_NoFireBelowThreshold(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// Only 4 distinct tactics — below chainMinTactics(5). Four used to fire; the
	// FP soak showed benign developer workstations reach four routinely.
	for i, tags := range [][]string{{"T1082"}, {"T1059"}, {"T1003"}, {"T1048"}} {
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
// kill-chain aggregator) now crosses the distinct-tactic threshold and fires.
func TestKillChainScorer_NewlyMappedTechniquesCorrelate(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	// audio capture (collection) → network sniffing (credential-access) →
	// protocol tunneling (C2) → resource hijacking (impact) → screen capture
	// (collection is already counted, so add discovery): chainMinTactics(5)
	// tactics, all from techniques added in the ⑤ expansion.
	seq := [][]string{
		{"T1123"}, // collection
		{"T1040"}, // credential-access
		{"T1572"}, // command-and-control
		{"T1496"}, // impact
		{"T1082"}, // discovery
	}
	var fired int
	for i, tags := range seq {
		fired += len(k.Observe("agentX", tags, base.Add(time.Duration(i)*time.Minute)))
	}
	if fired != 1 {
		t.Fatalf("newly-mapped 5-tactic chain should fire exactly 1 alert, got %d", fired)
	}
}

// TestKillChainScorer_FourTacticsDoNotFire pins the 2026-08-04 threshold raise.
//
// This scorer folds in every other match's MITRE tags, so its false positives are
// the other rules' false positives, summed. The FP soak measured it at 7,199.94
// /1000 hosts/day across 9 of 20 hosts and 4 of 5 profiles — the widest spread in
// the gate. The sequence below is what a developer workstation produces doing its
// job: `docker build` (execution + discovery), SSH key handling (credential-access
// + persistence). Four tactics, no attack.
//
// The raise is safe for detection rate because this alert carries MITRETags
// {"TA0000"}, a correlation marker rather than a technique, so it credits nothing
// in the ATT&CK measurement. Lowering the floor back to four would reintroduce the
// false positives without recovering any technique coverage.
func TestKillChainScorer_FourTacticsDoNotFire(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)
	benignDevWorkstation := [][]string{
		{"T1609"},     // container administration command → execution
		{"T1613"},     // container and resource discovery → discovery
		{"T1552.004"}, // private key file access → credential-access
		{"T1098.004"}, // ssh authorized_keys → persistence
	}
	for i, tags := range benignDevWorkstation {
		if m := k.Observe("dev-1", tags, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("開発端末の通常業務 (docker build + SSH鍵操作) が %d 戦術で発火しました。"+
				"この4戦術の組み合わせは FPソークで9ホストに出ていたもので、攻撃ではありません",
				i+1)
		}
	}
	// A fifth, unrelated tactic completes the chain and does fire — the rule is
	// tightened, not disabled.
	if m := k.Observe("dev-1", []string{"T1486"}, base.Add(5*time.Minute)); len(m) == 0 {
		t.Error("5戦術目 (impact) でも発火しませんでした。閾値を上げすぎて相関が死んでいます")
	}
}
