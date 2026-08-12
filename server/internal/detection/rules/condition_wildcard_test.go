package rules

import (
	"context"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
)

// TestExpandAllOfWildcards checks the syntactic rewrite in isolation.
func TestExpandAllOfWildcards(t *testing.T) {
	const rule = `
title: X
detection:
  selection_1_a:
    Image: a
  selection_1_b:
    Image: b
  selection_other:
    Image: c
  condition: all of selection_1_* or selection_other
`
	got := expandAllOfWildcards(rule)
	if !strings.Contains(got, "(selection_1_a and selection_1_b)") {
		t.Fatalf("all of selection_1_* not expanded to conjunction; got condition in:\n%s", got)
	}
	if strings.Contains(got, "all of selection_1_*") {
		t.Error("wildcard all-of survived the rewrite")
	}
	// The rewritten rule must now parse under sigma-go (the whole point).
	if _, err := sigma.ParseRule([]byte(got)); err != nil {
		t.Fatalf("rewritten rule still fails to parse: %v", err)
	}
}

// TestExpandAllOfWildcards_NoOp leaves supported/irrelevant conditions untouched.
func TestExpandAllOfWildcards_NoOp(t *testing.T) {
	for _, cond := range []string{"1 of selection_*", "all of them", "selection1 and selection2", "1 of them"} {
		rule := "title: X\ndetection:\n  selection1:\n    Image: a\n  selection2:\n    Image: b\n  condition: " + cond + "\n"
		got := expandAllOfWildcards(rule)
		if !strings.Contains(got, "condition: "+cond) {
			t.Errorf("condition %q should be unchanged, got:\n%s", cond, got)
		}
	}
}

// TestRuleEngine_ResurrectedAllOfRules drives the EXACT condition shapes of the
// 7 prod rules that were dead (sigma-go rejects `all of <prefix>*`) through the
// real engine and confirms they now compile AND fire.
func TestRuleEngine_ResurrectedAllOfRules(t *testing.T) {
	cases := []struct {
		id, content string
		event       map[string]interface{}
	}{
		{
			// Shadow Copies Deletion shape: (all of selN*) or (all of selM*)
			id: "shadowcopy",
			content: `
title: Shadow Copies Deletion
detection:
  selection1_img:
    Image|endswith: \vssadmin.exe
  selection1_cli:
    CommandLine|contains|all:
      - delete
      - shadows
  selection2_img:
    Image|endswith: \wmic.exe
  selection2_cli:
    CommandLine|contains: shadowcopy delete
  condition: (all of selection1_*) or (all of selection2_*)
`,
			event: map[string]interface{}{
				"type": "process", "agent_id": "h", "platform": "windows",
				"Image": `C:\Windows\System32\vssadmin.exe`, "CommandLine": `vssadmin delete shadows /all /quiet`,
			},
		},
		{
			// NTDS.DIT shape: 1 of selection* or all of set1*
			id: "ntds",
			content: `
title: NTDS DIT Exfil
detection:
  set1_a:
    Image|endswith: \ntdsutil.exe
  set1_b:
    CommandLine|contains: 'create full'
  condition: all of set1_*
`,
			event: map[string]interface{}{
				"type": "process", "agent_id": "h", "platform": "windows",
				"Image": `C:\Windows\System32\ntdsutil.exe`, "CommandLine": `ntdsutil "ac i ntds" "ifm" "create full c:\temp"`,
			},
		},
	}

	for _, c := range cases {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{sigmaRule(c.id, c.content)})
		m, err := e.Evaluate(context.Background(), c.event)
		if err != nil {
			t.Fatalf("%s: Evaluate: %v", c.id, err)
		}
		if !hasRule(m, c.id) {
			t.Errorf("%s: resurrected all-of rule should fire, got %d matches", c.id, len(m))
		}
	}
}
