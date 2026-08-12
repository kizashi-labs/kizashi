package detection

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Rule-health audit for the builtin Sigma rules.
//
// Motivation (2026-06-23): the Mimikatz rule shipped with `- lsadump::` / `- kerberos::`
// pattern values. A plain YAML scalar ending in ":" is parsed as a single-key MAP
// ({"lsadump:": nil}), NOT the string "lsadump::". The compiled rule then silently drops
// that pattern, so the technique is never detected — a SILENT 0% that compiles, loads, and
// even passes naive tests (the sibling `sekurlsa` pattern keeps the rule alive on other
// inputs). These tests catch that whole class structurally, across all current and future
// builtins, independent of any single rule's hand-written fixture.

// scalarOK reports whether v is an acceptable Sigma pattern leaf (a scalar). A map or
// sequence here means a value was mis-parsed — the trailing-colon trap, or a stray `: `
// turning a value into a mapping.
func scalarOK(v interface{}) bool {
	switch v.(type) {
	case string, int, int64, float64, bool, nil:
		return true
	default:
		return false
	}
}

// TestBuiltinSigmaNoMalformedPatterns walks every builtin rule's detection block and
// asserts that every selection field's value is a scalar or a list of scalars. A map where
// a scalar belongs is the YAML trailing-colon defect and is rejected with a pointed message.
func TestBuiltinSigmaNoMalformedPatterns(t *testing.T) {
	for _, ruleYAML := range builtinSigmaRules {
		var doc map[string]interface{}
		if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
			t.Errorf("builtin rule failed to parse as YAML: %v\n%.80q", err, ruleYAML)
			continue
		}
		title, _ := doc["title"].(string)
		if title == "" {
			t.Errorf("builtin rule has no title:\n%.80q", ruleYAML)
		}

		det, ok := doc["detection"].(map[string]interface{})
		if !ok {
			t.Errorf("rule %q has no detection map", title)
			continue
		}

		for selName, selVal := range det {
			if selName == "condition" || selName == "timeframe" {
				continue
			}
			selMap, ok := selVal.(map[string]interface{})
			if !ok {
				t.Errorf("rule %q: selection %q is not a field map (got %T) — malformed YAML?",
					title, selName, selVal)
				continue
			}
			for field, patterns := range selMap {
				switch pv := patterns.(type) {
				case []interface{}:
					for i, el := range pv {
						if !scalarOK(el) {
							t.Errorf("rule %q: selection %q field %q list item #%d parsed as %T, "+
								"want scalar — a value ending in ':' (e.g. \"lsadump::\") parses as a "+
								"map and the pattern is silently dropped; quote it.",
								title, selName, field, i, el)
						}
					}
				default:
					if !scalarOK(patterns) {
						t.Errorf("rule %q: selection %q field %q value parsed as %T, want scalar or "+
							"list — a value ending in ':' parses as a map and is silently dropped; quote it.",
							title, selName, field, patterns)
					}
				}
			}
		}
	}
}

// TestAllBuiltinRulesCompile guards another silent-death class: a rule that fails to
// compile is skipped by LoadBuiltinRules with its error swallowed, so the technique is
// undetected with no signal. Assert every shipped rule actually loads.
func TestAllBuiltinRulesCompile(t *testing.T) {
	e := NewSigmaEvaluator()
	loaded := LoadBuiltinRules(e)
	if loaded != len(builtinSigmaRules) {
		t.Errorf("only %d of %d builtin Sigma rules compiled — a rule failed to load and was "+
			"silently skipped (check for malformed YAML or unsupported detection syntax)",
			loaded, len(builtinSigmaRules))
	}
}
