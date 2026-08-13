package detection

import "testing"

func ruleYAML(title, field string) string {
	return "title: " + title + "\ndetection:\n  selection:\n    " + field + ": x\n  condition: selection"
}

// TestCurateBatch_GateAndCap verifies the two curate guarantees: field-unsupported
// rules never enable (stay Pending), and supported rules enable only up to the
// per-category cap per round (the rest Deferred) so a round reloads a bounded batch.
func TestCurateBatch_GateAndCap(t *testing.T) {
	supported := SupportedSigmaFields()
	rules := []SyncedRule{
		// registry category: 3 supported (TargetObject), cap will be 2.
		{ID: "r3", Category: "registry", Content: ruleYAML("reg3", "TargetObject|contains")},
		{ID: "r1", Category: "registry", Content: ruleYAML("reg1", "TargetObject|contains")},
		{ID: "r2", Category: "registry", Content: ruleYAML("reg2", "TargetObject|contains")},
		// process category: 1 supported.
		{ID: "p1", Category: "process_creation", Content: ruleYAML("proc1", "CommandLine|contains")},
		// unsupported field → must be Pending regardless of cap.
		{ID: "u1", Category: "registry", Content: ruleYAML("inert", "CallTrace")},
	}

	plan := CurateBatch(rules, 2, supported)

	// Unsupported is pending.
	if len(plan.Pending) != 1 || plan.Pending[0] != "u1" {
		t.Fatalf("Pending = %v, want [u1]", plan.Pending)
	}
	// registry capped at 2 (r1,r2 by ID order), r3 deferred; process p1 enabled.
	wantEnable := map[string]bool{"r1": true, "r2": true, "p1": true}
	if len(plan.Enable) != 3 {
		t.Fatalf("Enable = %v, want 3 (r1,r2,p1)", plan.Enable)
	}
	for _, id := range plan.Enable {
		if !wantEnable[id] {
			t.Errorf("unexpected enabled rule %q", id)
		}
	}
	if len(plan.Deferred) != 1 || plan.Deferred[0] != "r3" {
		t.Fatalf("Deferred = %v, want [r3] (over registry cap this round)", plan.Deferred)
	}
}

// TestCurateBatch_NoCap enables every supported rule when the cap is disabled.
func TestCurateBatch_NoCap(t *testing.T) {
	supported := SupportedSigmaFields()
	rules := []SyncedRule{
		{ID: "a", Category: "registry", Content: ruleYAML("a", "TargetObject|contains")},
		{ID: "b", Category: "registry", Content: ruleYAML("b", "TargetObject|contains")},
		{ID: "c", Category: "registry", Content: ruleYAML("c", "Details|endswith")},
	}
	plan := CurateBatch(rules, 0, supported)
	if len(plan.Enable) != 3 || len(plan.Deferred) != 0 || len(plan.Pending) != 0 {
		t.Fatalf("no-cap: Enable=%v Deferred=%v Pending=%v, want all 3 enabled",
			plan.Enable, plan.Deferred, plan.Pending)
	}
}

// TestCurateBatch_SuccessiveRoundsAdvance confirms that enabling this round's batch
// and re-running curate on the remainder drains the backlog (no rule is stuck).
func TestCurateBatch_SuccessiveRoundsAdvance(t *testing.T) {
	supported := SupportedSigmaFields()
	all := []SyncedRule{
		{ID: "r1", Category: "registry", Content: ruleYAML("r1", "TargetObject|contains")},
		{ID: "r2", Category: "registry", Content: ruleYAML("r2", "TargetObject|contains")},
		{ID: "r3", Category: "registry", Content: ruleYAML("r3", "TargetObject|contains")},
	}
	enabled := map[string]bool{}
	remaining := all
	for round := 0; round < 5 && len(remaining) > 0; round++ {
		plan := CurateBatch(remaining, 1, supported)
		if len(plan.Enable) == 0 {
			break // nothing more enableable
		}
		for _, id := range plan.Enable {
			enabled[id] = true
		}
		// Drop the just-enabled rules; re-run on the rest.
		var next []SyncedRule
		for _, r := range remaining {
			if !enabled[r.ID] {
				next = append(next, r)
			}
		}
		remaining = next
	}
	if len(enabled) != 3 {
		t.Fatalf("successive rounds should drain all 3 supported rules, enabled=%v", enabled)
	}
}
