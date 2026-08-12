package remediation

import (
	"encoding/json"
	"testing"
)

// TestBuiltinRules_WellFormed validates the shipped auto-remediation rules: each
// must have an ID, a name, an "alert" trigger, and at least one action. A broken
// built-in rule would silently ship a non-functional auto-response.
func TestBuiltinRules_WellFormed(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) == 0 {
		t.Fatal("expected built-in remediation rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Name == "" {
			t.Errorf("rule missing ID/Name: %+v", r)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true
		if r.Trigger.EventType != "alert" {
			t.Errorf("rule %s: expected EventType 'alert', got %q", r.ID, r.Trigger.EventType)
		}
		if len(r.Actions) == 0 {
			t.Errorf("rule %s has no actions", r.ID)
		}
	}
}

func TestLoadBuiltins(t *testing.T) {
	e := NewEngine(nil, nil)
	LoadBuiltins(e)
	if got, want := len(e.GetRules()), len(BuiltinRules()); got != want {
		t.Errorf("LoadBuiltins loaded %d rules, want %d", got, want)
	}
}

// TestBuiltinRules_CriticalAlertMatches confirms the critical-isolate rule fires
// for a severity-9 alert (the auto-isolation path).
func TestBuiltinRules_CriticalAlertMatches(t *testing.T) {
	e := NewEngine(nil, nil)
	var critical *RemediationRule
	for _, r := range BuiltinRules() {
		if r.ID == "rem-001-critical-isolate" {
			critical = r
			break
		}
	}
	if critical == nil {
		t.Fatal("built-in critical-isolate rule not found")
	}
	if !e.triggerMatches(critical.Trigger, "alert", 9, nil) {
		t.Error("severity-9 alert should match the critical auto-isolate rule")
	}
	if e.triggerMatches(critical.Trigger, "alert", 3, nil) {
		t.Error("a low-severity alert must NOT trigger auto-isolation")
	}
}

// ─── JSON helpers ───────────────────────────────────────────────────────────

func TestBuildActionsJSON(t *testing.T) {
	if got := buildActionsJSON(nil); got != "[]" {
		t.Errorf("empty actions should be []: got %q", got)
	}

	actions := []ActionResult{
		{ActionType: "isolate_network", Success: true, Message: "isolated host-1"},
		{ActionType: "notify", Success: false, Message: `failed: "timeout"`}, // embedded quotes
	}
	out := buildActionsJSON(actions)

	// Output must be valid JSON and round-trip back to the same fields.
	var parsed []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("buildActionsJSON produced invalid JSON: %v\n%s", err, out)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(parsed))
	}
	if parsed[0]["action_type"] != "isolate_network" || parsed[0]["success"] != true {
		t.Errorf("first action wrong: %+v", parsed[0])
	}
	if parsed[1]["message"] != `failed: "timeout"` {
		t.Errorf("embedded quotes not preserved: %+v", parsed[1])
	}
}

func TestNullableUUID(t *testing.T) {
	if nullableUUID("") != nil {
		t.Error("empty id should map to nil (SQL NULL)")
	}
	if nullableUUID("abc-123") != "abc-123" {
		t.Error("non-empty id should pass through")
	}
}
