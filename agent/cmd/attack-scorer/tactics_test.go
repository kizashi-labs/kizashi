package main

import "testing"

// validTactics is the closed set of ATT&CK Enterprise tactic names the scorecard uses.
var validTactics = map[string]bool{
	"initial-access": true, "execution": true, "persistence": true,
	"privilege-escalation": true, "defense-evasion": true, "credential-access": true,
	"discovery": true, "lateral-movement": true, "collection": true,
	"command-and-control": true, "exfiltration": true, "impact": true,
}

// TestTacticsMap_OnlyKnownTactics guards against a typo'd tactic name (e.g.
// "priv-esc") that would silently mis-bucket a technique in the scorecard.
func TestTacticsMap_OnlyKnownTactics(t *testing.T) {
	for tech, tacs := range techniqueTactics {
		if len(tacs) == 0 {
			t.Errorf("%s maps to no tactic", tech)
		}
		for _, ta := range tacs {
			if !validTactics[ta] {
				t.Errorf("%s maps to unknown tactic %q", tech, ta)
			}
		}
	}
}

// TestTacticsMap_CoversDetectedTechniques is a precision regression guard: every
// technique the platform's builtin rules detect must be Tactic-rankable, else a real
// detection scores None for lack of a tactic. This lists the bases that were filled on
// 2026-07-09 plus a few core ones; add here when a new builtin technique is shipped.
func TestTacticsMap_CoversDetectedTechniques(t *testing.T) {
	mustMap := []string{
		// 2026-07-09 precision fill
		"T1068", "T1202", "T1216", "T1484", "T1539", "T1556", "T1609", "T1610",
		// core techniques the coverage corpus exercises
		"T1059", "T1003", "T1021", "T1071", "T1547", "T1486", "T1567", "T1123",
	}
	for _, tech := range mustMap {
		if _, ok := techniqueTactics[tech]; !ok {
			t.Errorf("detected technique %s is missing from techniqueTactics — scorer cannot Tactic-rank it", tech)
		}
	}
}
