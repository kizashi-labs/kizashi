package detection

import (
	"fmt"
	"testing"
)

// sprintfRule fills a rule template's %s placeholder (used for the condition).
func sprintfRule(tmpl, cond string) string {
	return fmt.Sprintf(tmpl, cond)
}

// loadOne is a helper that builds an evaluator with a single rule, failing the
// test if the rule does not compile.
func loadOne(t *testing.T, yaml string) *SigmaEvaluator {
	t.Helper()
	e := NewSigmaEvaluator()
	if err := e.LoadRule(yaml); err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}
	return e
}

// matched reports whether the given event matches at least one rule.
func matched(e *SigmaEvaluator, event map[string]interface{}) bool {
	return len(e.EvaluateEvent(event)) > 0
}

// ─── Loading / lifecycle ────────────────────────────────────────────────────

func TestSigmaEvaluator_LoadCountClear(t *testing.T) {
	e := NewSigmaEvaluator()
	if e.RuleCount() != 0 {
		t.Fatalf("new evaluator should have 0 rules, got %d", e.RuleCount())
	}
	rule := `
title: T1
level: low
detection:
  selection:
    Image|endswith: \x.exe
  condition: selection
`
	if err := e.LoadRule(rule); err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	if e.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", e.RuleCount())
	}
	e.ClearRules()
	if e.RuleCount() != 0 {
		t.Fatalf("ClearRules should reset to 0, got %d", e.RuleCount())
	}
}

func TestSigmaEvaluator_InvalidRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"garbage", "::: not yaml :::"},
		{"missing title", "detection:\n  selection:\n    A: b\n  condition: selection\n"},
		{"missing condition", "title: NoCond\ndetection:\n  selection:\n    A: b\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewSigmaEvaluator()
			if err := e.LoadRule(tc.yaml); err == nil {
				t.Errorf("expected LoadRule to fail for %q", tc.name)
			}
		})
	}
}

func TestSigmaEvaluator_InvalidRegexModifier(t *testing.T) {
	e := NewSigmaEvaluator()
	rule := `
title: BadRegex
detection:
  selection:
    Field|re: '([unterminated'
  condition: selection
`
	if err := e.LoadRule(rule); err == nil {
		t.Error("expected LoadRule to fail on invalid regex")
	}
}

// ─── Field modifiers ────────────────────────────────────────────────────────

func TestSigmaEvaluator_Modifiers(t *testing.T) {
	cases := []struct {
		name  string
		field string // "Field|modifier"
		value string // YAML scalar
		event interface{}
		want  bool
	}{
		// default modifier is a case-insensitive substring (contains) match
		{"default contains hit", "Image", "powershell", `C:\Windows\powershell.exe`, true},
		{"default contains case-insensitive", "Image", "POWERSHELL", `c:\windows\powershell.exe`, true},
		{"default contains miss", "Image", "cmd.exe", `C:\Windows\powershell.exe`, false},
		{"startswith hit", "Image|startswith", `C:\Windows`, `C:\Windows\powershell.exe`, true},
		{"startswith miss", "Image|startswith", `C:\Temp`, `C:\Windows\powershell.exe`, false},
		{"endswith hit", "Image|endswith", `\powershell.exe`, `C:\Windows\powershell.exe`, true},
		{"endswith miss", "Image|endswith", `\cmd.exe`, `C:\Windows\powershell.exe`, false},
		{"contains hit", "CommandLine|contains", "-enc", "powershell -enc ABC", true},
		{"re hit", "CommandLine|re", "-e(nc)?\\b", "powershell -enc ABC", true},
		{"re miss", "CommandLine|re", "^cmd", "powershell -enc ABC", false},
		{"numeric field stringified", "EventID", "4625", 4625, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := "title: M\ndetection:\n  selection:\n    " +
				tc.field + ": '" + tc.value + "'\n  condition: selection\n"
			e := loadOne(t, rule)
			got := matched(e, map[string]interface{}{fieldName(tc.field): tc.event})
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// fieldName strips a "|modifier" suffix from a field key.
func fieldName(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i]
		}
	}
	return key
}

func TestSigmaEvaluator_ContainsAll(t *testing.T) {
	rule := `
title: AllOfThem
detection:
  selection:
    CommandLine|contains|all:
      - foo
      - bar
  condition: selection
`
	e := loadOne(t, rule)
	if !matched(e, map[string]interface{}{"CommandLine": "x foo y bar z"}) {
		t.Error("expected match when both foo and bar present")
	}
	if matched(e, map[string]interface{}{"CommandLine": "x foo y z"}) {
		t.Error("expected no match when only foo present (|all requires both)")
	}
}

func TestSigmaEvaluator_ListValueIsOR(t *testing.T) {
	rule := `
title: ListOR
detection:
  selection:
    EventID:
      - "4624"
      - "4625"
  condition: selection
`
	e := loadOne(t, rule)
	if !matched(e, map[string]interface{}{"EventID": "4625"}) {
		t.Error("expected match for one of the listed values (OR)")
	}
	if matched(e, map[string]interface{}{"EventID": "1234"}) {
		t.Error("expected no match for an unlisted value")
	}
}

// ─── Selection structure (AND within a map, OR across list-of-maps) ──────────

func TestSigmaEvaluator_SelectionMapIsAND(t *testing.T) {
	rule := `
title: TwoFields
detection:
  selection:
    Image|endswith: \powershell.exe
    CommandLine|contains: -enc
  condition: selection
`
	e := loadOne(t, rule)
	full := map[string]interface{}{"Image": `C:\powershell.exe`, "CommandLine": "x -enc y"}
	if !matched(e, full) {
		t.Error("expected match when both fields satisfied")
	}
	if matched(e, map[string]interface{}{"Image": `C:\powershell.exe`, "CommandLine": "x y"}) {
		t.Error("expected no match when one field fails (AND)")
	}
	if matched(e, map[string]interface{}{"Image": `C:\powershell.exe`}) {
		t.Error("expected no match when a required field is missing")
	}
}

func TestSigmaEvaluator_SelectionListOfMapsIsOR(t *testing.T) {
	rule := `
title: ListOfMaps
detection:
  selection:
    - Image|endswith: \powershell.exe
    - Image|endswith: \cmd.exe
  condition: selection
`
	e := loadOne(t, rule)
	if !matched(e, map[string]interface{}{"Image": `C:\cmd.exe`}) {
		t.Error("expected match for second map in the OR list")
	}
	if matched(e, map[string]interface{}{"Image": `C:\notepad.exe`}) {
		t.Error("expected no match when neither map matches")
	}
}

func TestSigmaEvaluator_CaseInsensitiveFieldName(t *testing.T) {
	rule := `
title: CIField
detection:
  selection:
    Image|endswith: \powershell.exe
  condition: selection
`
	e := loadOne(t, rule)
	// event uses lowercase "image" — lookup must still resolve it
	if !matched(e, map[string]interface{}{"image": `C:\powershell.exe`}) {
		t.Error("expected case-insensitive field-name lookup to match")
	}
}

// ─── Condition expressions ──────────────────────────────────────────────────

func TestSigmaEvaluator_ConditionLogic(t *testing.T) {
	rule := `
title: Logic
detection:
  selA:
    A|contains: a
  selB:
    B|contains: b
  condition: %s
`
	type ev = map[string]interface{}
	cases := []struct {
		name      string
		condition string
		event     ev
		want      bool
	}{
		{"and both", "selA and selB", ev{"A": "a", "B": "b"}, true},
		{"and missing one", "selA and selB", ev{"A": "a"}, false},
		{"or first", "selA or selB", ev{"A": "a"}, true},
		{"or none", "selA or selB", ev{"C": "c"}, false},
		{"not hit", "selA and not selB", ev{"A": "a"}, true},
		{"not blocked", "selA and not selB", ev{"A": "a", "B": "b"}, false},
		{"parens", "( selA or selB ) and selA", ev{"A": "a"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := sprintfRule(rule, tc.condition)
			e := loadOne(t, y)
			if got := matched(e, tc.event); got != tc.want {
				t.Errorf("condition %q: got %v, want %v", tc.condition, got, tc.want)
			}
		})
	}
}

func TestSigmaEvaluator_OneOfAndAllOf(t *testing.T) {
	rule := `
title: Quant
detection:
  sel_a:
    A|contains: a
  sel_b:
    B|contains: b
  condition: %s
`
	type ev = map[string]interface{}
	cases := []struct {
		name      string
		condition string
		event     ev
		want      bool
	}{
		{"1 of matches one", "1 of sel_*", ev{"A": "a"}, true},
		{"1 of matches none", "1 of sel_*", ev{"C": "c"}, false},
		{"all of needs every", "all of sel_*", ev{"A": "a", "B": "b"}, true},
		{"all of missing one", "all of sel_*", ev{"A": "a"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := loadOne(t, sprintfRule(rule, tc.condition))
			if got := matched(e, tc.event); got != tc.want {
				t.Errorf("condition %q: got %v, want %v", tc.condition, got, tc.want)
			}
		})
	}
}

// ─── Result payload + multiple rules ────────────────────────────────────────

func TestSigmaEvaluator_MatchPayload(t *testing.T) {
	rule := `
title: Payload Rule
level: critical
tags:
  - attack.execution
  - t1059
detection:
  selection:
    Image|endswith: \powershell.exe
  condition: selection
`
	e := loadOne(t, rule)
	event := map[string]interface{}{"Image": `C:\powershell.exe`}
	matches := e.EvaluateEvent(event)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.RuleTitle != "Payload Rule" {
		t.Errorf("RuleTitle: got %q", m.RuleTitle)
	}
	if m.Level != "critical" {
		t.Errorf("Level: got %q, want critical (lowercased)", m.Level)
	}
	if len(m.Tags) != 2 || m.Tags[0] != "attack.execution" {
		t.Errorf("Tags not propagated: %v", m.Tags)
	}
	if m.MatchedFields["Image"] != `C:\powershell.exe` {
		t.Errorf("MatchedFields not propagated: %v", m.MatchedFields)
	}
}

func TestSigmaEvaluator_MultipleRules(t *testing.T) {
	e := NewSigmaEvaluator()
	r1 := "title: R1\ndetection:\n  selection:\n    Image|endswith: \\powershell.exe\n  condition: selection\n"
	r2 := "title: R2\ndetection:\n  selection:\n    Image|contains: powershell\n  condition: selection\n"
	r3 := "title: R3\ndetection:\n  selection:\n    Image|endswith: \\cmd.exe\n  condition: selection\n"
	for _, r := range []string{r1, r2, r3} {
		if err := e.LoadRule(r); err != nil {
			t.Fatalf("LoadRule: %v", err)
		}
	}
	matches := e.EvaluateEvent(map[string]interface{}{"Image": `C:\powershell.exe`})
	// R1 and R2 should fire, R3 should not.
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (R1,R2), got %d: %+v", len(matches), matches)
	}
	titles := map[string]bool{}
	for _, m := range matches {
		titles[m.RuleTitle] = true
	}
	if !titles["R1"] || !titles["R2"] || titles["R3"] {
		t.Errorf("unexpected matched rule set: %v", titles)
	}
}

func TestSigmaEvaluator_NoMatchIsEmpty(t *testing.T) {
	e := loadOne(t, "title: NM\ndetection:\n  selection:\n    Image|endswith: \\x.exe\n  condition: selection\n")
	if got := e.EvaluateEvent(map[string]interface{}{"Image": `C:\y.exe`}); len(got) != 0 {
		t.Errorf("expected no matches, got %d", len(got))
	}
}
