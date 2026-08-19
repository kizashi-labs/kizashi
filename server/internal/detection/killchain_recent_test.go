package detection

import (
	"strings"
	"testing"
	"time"
)

// TestTacticForTechnique_RecentCoverage guards that the techniques emitted by the
// detections added in this work map to a kill-chain tactic (not "unknown"), so they
// actually contribute to cross-signal kill-chain correlation. If a future edit drops one
// of these from tacticForTechnique, the technique would silently stop strengthening the
// correlation — this test fails instead.
func TestTacticForTechnique_RecentCoverage(t *testing.T) {
	want := map[string]string{
		// process-ancestry anomalies
		"T1036":     "defense-evasion",
		"T1055.012": "privilege-escalation",
		"T1068":     "privilege-escalation",
		"T1203":     "execution",
		"T1059.002": "execution",
		"T1053.003": "execution",
		// cloud
		"T1552.005": "credential-access",
		"T1552.007": "credential-access",
		"T1526":     "discovery",
		"T1190":     "initial-access",
		// network C2 / DNS
		"T1568.001": "command-and-control",
		"T1071.001": "command-and-control",
		"T1573.002": "command-and-control",
		// defense-evasion registry
		"T1562.004": "defense-evasion",
		"T1548.002": "privilege-escalation",
	}
	for tech, tactic := range want {
		if got := tacticForTechnique(tech); got != tactic {
			t.Errorf("tacticForTechnique(%s) = %q, want %q", tech, got, tactic)
		}
	}
}

// TestKillChain_RecentDetectionsCorrelate proves the recent detections combine into a
// kill-chain alert: an svchost-hollowing (priv-esc), a JA3/beacon C2 (command-and-control),
// a cloud-credential theft (credential-access), and a cloud discovery (discovery) on one
// host cross the distinct-tactic threshold and raise a correlated multi-stage alert.
func TestKillChain_RecentDetectionsCorrelate(t *testing.T) {
	k := newKillChainScorer()
	base := time.Unix(1_700_000_000, 0)

	// chainMinTactics(5) distinct tactics from recent detection classes, within
	// the window.
	steps := [][]string{
		{"T1055.012"}, // svchost hollowing → privilege-escalation
		{"T1071.001"}, // JA3/beacon C2 → command-and-control
		{"T1552.005"}, // IMDS credential theft → credential-access
		{"T1526"},     // cloud service discovery → discovery
		{"T1486"},     // ransomware encryption → impact
	}
	var got []string
	for i, tags := range steps {
		for _, m := range k.Observe("agent-1", tags, base.Add(time.Duration(i)*time.Minute)) {
			got = append(got, m.Title)
		}
	}
	if len(got) == 0 {
		t.Fatal("five distinct-tactic recent detections should raise a kill-chain correlation")
	}
	if !strings.Contains(got[len(got)-1], "KILLCHAIN") {
		t.Errorf("expected a KILLCHAIN correlation title, got %q", got[len(got)-1])
	}
}
