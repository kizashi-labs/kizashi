package detection

import "testing"

// DB Sigma rules must stay OS-scoped after moving to this engine.
//
// server-detect gated them on the `rules.platform` column — that is what kept a
// macOS-only rule off Linux telemetry. This pipeline never had any platform
// scoping of its own, so when SetDBSigmaEvaluation handed the rules over, the
// gate would have been lost with the engine that applied it.
//
// Scope, stated honestly: a soak on a benign Linux/Windows fleet measured NO
// change from this gate (271 detection rows either way). The 8 macOS-rule
// firings that first drew attention to OS scoping turned out to come from a
// BUILTIN — "macOS Ingress Tool Transfer via curl/osascript", whose scoping
// lives in logsource.product and is deliberately not enforced (P4-9) — not from
// a DB rule this gate covers. The gate restores a property the ownership move
// removed; it is not a false-positive reduction, and this test is the only
// evidence that it works, because the fleet never exercised it.
//
// The gate itself is rules.PlatformMatchesEvent, reused rather than
// reimplemented so both engines stay on one set of contract tests.
func TestDBRulePlatformGateInAPIEvaluator(t *testing.T) {
	const macRule = `
title: macOS-only tool transfer
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'curl '
  condition: selection`

	fires := func(ev *SigmaEvaluator, platform string) bool {
		event := map[string]interface{}{
			"type":         "process",
			"platform":     platform,
			"image_path":   "/usr/bin/curl",
			"command_line": "curl https://example.com/x -o /tmp/x",
		}
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == "macOS-only tool transfer" {
				return true
			}
		}
		return false
	}

	t.Run("macOS rule does not fire on Linux telemetry", func(t *testing.T) {
		ev := NewSigmaEvaluator()
		if err := ev.loadDBRule(macRule, nil, 5, []string{"macos"}); err != nil {
			t.Fatalf("load: %v", err)
		}
		if fires(ev, "linux") {
			t.Error("a macOS-scoped DB rule matched a Linux event. The platform column is " +
				"either not being carried into this evaluator or not being checked — the OS " +
				"scoping that server-detect applied to these rules has been lost with the move.")
		}
	})

	t.Run("and still fires on its own platform", func(t *testing.T) {
		ev := NewSigmaEvaluator()
		if err := ev.loadDBRule(macRule, nil, 5, []string{"macos"}); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !fires(ev, "macos") {
			t.Error("the rule stopped firing on macOS too — the gate is suppressing the " +
				"detection it was supposed to scope, not scope it")
		}
		// darwin≡macos is pinned by rules.TestPlatformMatchesEvent; assert the api
		// side inherits it rather than growing its own spelling table.
		if !fires(ev, "darwin") {
			t.Error(`platform "darwin" was gated out of a macos rule — the api path is not ` +
				"using rules.PlatformMatchesEvent's canonical spellings")
		}
	})

	t.Run("unknown event OS fails open", func(t *testing.T) {
		ev := NewSigmaEvaluator()
		if err := ev.loadDBRule(macRule, nil, 5, []string{"macos"}); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !fires(ev, "") {
			t.Error("an event with no platform was gated out. The gate must fail OPEN: a " +
				"missing label is a telemetry gap, and silently dropping detections for it " +
				"is indistinguishable from having no rules at all (see P5-24).")
		}
	})

	t.Run("builtins are never platform-gated", func(t *testing.T) {
		ev := NewSigmaEvaluator()
		if err := ev.LoadRule(macRule); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !fires(ev, "linux") {
			t.Error("a builtin was platform-gated. Builtins carry no platform column; " +
				"gating them on an empty list would silence the entire builtin corpus.")
		}
	})
}
