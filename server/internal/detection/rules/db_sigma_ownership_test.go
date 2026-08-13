package rules

import (
	"context"
	"testing"
)

// The switch has to actually stop the second evaluation, and it has to stop
// ONLY that.
//
// The failure this guards is not "the flag is ignored" — that would show up
// immediately. It is the opposite: a future edit that gates too much and takes
// the sequence/behavioural rules down with the Sigma ones. Those have no
// counterpart in the api server, so losing them is a silent coverage loss that
// no alert-count comparison would attribute to this change.
func TestDBSigmaOwnershipGate(t *testing.T) {
	sigmaRule := &DetectionRule{
		ID: "s1", Name: "Sigma one", Type: "sigma", Enabled: true,
		Content: `
title: Sigma one
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection`,
	}
	event := map[string]interface{}{
		"agent_id": "h", "type": "process", "command_line": "x mimikatz y",
	}

	t.Run("owned here: the rule is compiled and fires", func(t *testing.T) {
		e := NewRuleEngine()
		e.SetPlatformGate(false)
		e.SetDBSigmaEvaluation(true)
		e.LoadRules([]*DetectionRule{sigmaRule})

		m, err := e.Evaluate(context.Background(), event)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if len(m) == 0 {
			t.Fatal("a DB Sigma rule this engine owns did not fire — the gate is " +
				"suppressing rules it was told to evaluate")
		}
	})

	t.Run("owned by the api: the rule is not evaluated here", func(t *testing.T) {
		e := NewRuleEngine()
		e.SetPlatformGate(false)
		e.SetDBSigmaEvaluation(false)
		e.LoadRules([]*DetectionRule{sigmaRule})

		m, err := e.Evaluate(context.Background(), event)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if len(m) != 0 {
			t.Fatalf("a DB Sigma rule owned by the api still fired here (%d matches) — "+
				"the double evaluation this switch exists to remove is still happening, and "+
				"every matching event will produce two alert rows", len(m))
		}
	})

	// The rule stays addressable either way: handlers and the correlation layer
	// look rules up by ID, and skipping COMPILATION must not mean forgetting the
	// rule exists.
	t.Run("the rule is still registered when the api owns it", func(t *testing.T) {
		e := NewRuleEngine()
		e.SetDBSigmaEvaluation(false)
		e.LoadRules([]*DetectionRule{sigmaRule})
		if got := e.GetRule("s1"); got == nil {
			t.Error("GetRule lost the rule when ownership moved to the api — the gate is " +
				"dropping rules from the registry, not just from compilation")
		}
	})
}
