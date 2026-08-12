package correlation

import (
	"context"
	"testing"
)

// TestBuiltinRulesFire is a regression guard for the bug where every built-in
// correlation rule was inert: the rules filter on Sysmon-style sub-types
// ("auth_failure", "lsass_access", …) but the pipeline only passed the base
// event category ("auth", "process", …), so no rule could ever match. Each
// sub-test drives a representative alert stream through ProcessAlert and asserts
// the corresponding incident is created.
func TestBuiltinRulesFire(t *testing.T) {
	ctx := context.Background()

	t.Run("lateral movement (brute force auth)", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		authFail := map[string]interface{}{"success": false}
		var inc *Incident
		for i := 0; i < 5; i++ { // MinEvents = 5
			inc = e.ProcessAlert(ctx, id(i), agent(i), "auth", "T1110", 8, authFail)
		}
		if inc == nil {
			t.Fatal("corr-001 lateral movement should fire after 5 auth-failure alerts")
		}
	})

	t.Run("credential dumping campaign", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		var inc *Incident
		for i := 0; i < 3; i++ { // MinEvents = 3, severity >= 7
			inc = e.ProcessAlert(ctx, id(i), agent(i), "process", "T1003.001", 8, nil)
		}
		if inc == nil {
			t.Fatal("corr-002 credential dumping should fire after 3 T1003 alerts across agents")
		}
	})

	t.Run("ransomware outbreak", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		var inc *Incident
		for i := 0; i < 5; i++ { // MinEvents = 5, severity >= 8
			inc = e.ProcessAlert(ctx, id(i), agent(i), "file", "T1486", 9, nil)
		}
		if inc == nil {
			t.Fatal("corr-003 ransomware outbreak should fire after 5 T1486 alerts across agents")
		}
	})

	t.Run("persistence establishment", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		// MinEvents = 2, severity >= 5: a registry modification + a scheduled task.
		e.ProcessAlert(ctx, "p1", "agent-x", "registry", "T1112", 6, nil)
		inc := e.ProcessAlert(ctx, "p2", "agent-x", "process", "T1053.005", 6, nil)
		if inc == nil {
			t.Fatal("corr-004 persistence should fire on registry + scheduled-task within window")
		}
	})

	t.Run("c2 beaconing", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		var inc *Incident
		for i := 0; i < 8; i++ { // MinEvents = 8, severity >= 4
			inc = e.ProcessAlert(ctx, id(i), "agent-c2", "network", "T1071.001", 5, nil)
		}
		if inc == nil {
			t.Fatal("corr-005 C2 beaconing should fire after 8 network alerts")
		}
	})
}

// TestBuiltinRulesNoFalsePositive verifies the high-severity, low-threshold
// rules stay gated on MITRE technique: benign file/process alerts that lack an
// impact/credential-access technique must never raise a ransomware or
// credential-dumping incident.
func TestBuiltinRulesNoFalsePositive(t *testing.T) {
	ctx := context.Background()

	t.Run("benign file alerts do not trip ransomware", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		for i := 0; i < 10; i++ {
			e.ProcessAlert(ctx, id(i), agent(i), "file", "", 9, nil) // no impact technique
		}
		if n := e.GetStats().TotalIncidents; n != 0 {
			t.Fatalf("benign file alerts must not create incidents, got %d", n)
		}
	})

	t.Run("benign process alerts do not trip credential dumping", func(t *testing.T) {
		e := NewEngine(nil)
		LoadBuiltins(e)
		for i := 0; i < 10; i++ {
			e.ProcessAlert(ctx, id(i), agent(i), "process", "T1059", 8, nil) // execution, not cred-access
		}
		if n := e.GetStats().TotalIncidents; n != 0 {
			t.Fatalf("benign process alerts must not create incidents, got %d", n)
		}
	})
}

func id(i int) string    { return "alert-" + string(rune('a'+i)) }
func agent(i int) string { return "agent-" + string(rune('a'+i)) }
