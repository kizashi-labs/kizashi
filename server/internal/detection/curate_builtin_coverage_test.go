package detection

import "testing"

// The builtin ruleset must actually yield coverage keys. If sigmaTechniques or
// RuleCategory ever stops parsing the builtin YAML shape, the gate would silently
// become a no-op and duplicates would flow back in — a failure that is invisible
// except through a rising FP count weeks later.
func TestBuiltinCoverageIsNotEmpty(t *testing.T) {
	cov := BuiltinCoverage()
	if len(cov) < 100 {
		t.Fatalf("builtin coverage = %d keys, expected the 301 builtin rules to yield far more; "+
			"tag or logsource parsing is probably broken", len(cov))
	}
	// Spot-check a pair that must be present: Mimikatz is tagged attack.t1003 in
	// process_creation.
	if !cov[builtinCoverageKey("T1003", "process_creation")] {
		t.Error("T1003|process_creation missing from builtin coverage")
	}
}

func TestSigmaTechniquesExtractsAllTechniquesNotTactics(t *testing.T) {
	got := sigmaTechniques(`
title: x
tags:
  - attack.t1087.002
  - attack.discovery
  - attack.t1069.002
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\net.exe'
  condition: selection
`)
	if len(got) != 2 || got[0] != "T1087.002" || got[1] != "T1069.002" {
		t.Fatalf("sigmaTechniques = %v, want [T1087.002 T1069.002] (tactics excluded, all techniques kept)", got)
	}
}

// The eight FP-soak duplicates that migration 373 could not reach: they are
// source='sigmahq' rows, so only this gate can stop them coming back.
func TestGateCatchesFPSoakDuplicates(t *testing.T) {
	cov := map[string]bool{
		builtinCoverageKey("T1609", "process_creation"):     true, // Container Administration Command
		builtinCoverageKey("T1087.002", "process_creation"): true, // Domain Account Discovery
	}
	dup := SyncedRule{
		ID: "sync-1", Category: "process_creation",
		Content: "title: Container Administration Command\ntags:\n  - attack.t1609\nlogsource:\n  category: process_creation\n",
	}
	if !duplicatesBuiltin(dup, cov) {
		t.Error("a synced rule whose technique×logsource a builtin covers was not flagged as duplicate")
	}
}

// The gate must key on BOTH technique and logsource. The same technique observed
// through a different logsource is a genuinely different detection — the SSH
// authorized_keys pair proved this: one builtin watches file_event, another
// watches process_creation, and only the file_event one was a real duplicate.
func TestSameTechniqueDifferentLogsourceIsNotDuplicate(t *testing.T) {
	cov := map[string]bool{builtinCoverageKey("T1098.004", "file_event"): true}
	r := SyncedRule{
		ID: "sync-2", Category: "process_creation",
		Content: "title: authorized_keys via shell\ntags:\n  - attack.t1098.004\nlogsource:\n  category: process_creation\n",
	}
	if duplicatesBuiltin(r, cov) {
		t.Error("same technique in a different logsource must not be treated as a duplicate")
	}
}

// An untagged rule has nothing to compare; withholding it would hide a detection
// for a reason invisible in the status view.
func TestUntaggedRuleIsNeverDuplicate(t *testing.T) {
	cov := map[string]bool{builtinCoverageKey("T1609", "process_creation"): true}
	r := SyncedRule{ID: "sync-3", Category: "process_creation",
		Content: "title: no tags\nlogsource:\n  category: process_creation\n"}
	if duplicatesBuiltin(r, cov) {
		t.Error("a rule with no attack.t* tag must not be flagged as a duplicate")
	}
}

// A duplicate must not consume a per-category slot, otherwise the gate would
// reduce how much genuinely new coverage each round can turn on.
func TestDuplicateDoesNotConsumeCategoryCap(t *testing.T) {
	supported := SupportedSigmaFields()
	newRule := func(id, tech string) SyncedRule {
		return SyncedRule{ID: id, Category: "process_creation",
			Content: "title: " + id + "\ntags:\n  - attack." + tech +
				"\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n" +
				"  selection:\n    CommandLine|contains: " + id + "\n  condition: selection\n"}
	}
	rules := []SyncedRule{newRule("a-dup", "t1609"), newRule("b-new", "t1570")}
	cov := map[string]bool{builtinCoverageKey("T1609", "process_creation"): true}

	plan := CurateBatchWith(rules, 1, supported, cov)

	if len(plan.Duplicate) != 1 || plan.Duplicate[0] != "a-dup" {
		t.Fatalf("Duplicate = %v, want [a-dup]", plan.Duplicate)
	}
	// Cap is 1. "a-dup" sorts first; if it had consumed the slot, "b-new" would be
	// deferred and the round would enable nothing new.
	if len(plan.Enable) != 1 || plan.Enable[0] != "b-new" {
		t.Fatalf("Enable = %v, want [b-new]: a duplicate consumed the per-category slot", plan.Enable)
	}
}

// CurateBatch keeps its old behaviour so existing callers and tests are unaffected.
func TestCurateBatchWithoutCoverageGateIsUnchanged(t *testing.T) {
	supported := SupportedSigmaFields()
	r := SyncedRule{ID: "z", Category: "process_creation",
		Content: "title: z\ntags:\n  - attack.t1609\nlogsource:\n  category: process_creation\n  product: windows\n" +
			"detection:\n  selection:\n    CommandLine|contains: docker\n  condition: selection\n"}
	plan := CurateBatch([]SyncedRule{r}, 0, supported)
	if len(plan.Duplicate) != 0 {
		t.Fatalf("CurateBatch (no coverage) reported duplicates: %v", plan.Duplicate)
	}
	if len(plan.Enable) != 1 {
		t.Fatalf("Enable = %v, want the rule enabled", plan.Enable)
	}
}
