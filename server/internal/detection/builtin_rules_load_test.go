package detection

import (
	"fmt"
	"strings"
	"testing"
)

// Every built-in Sigma rule must compile.
//
// This file is the entire Sigma layer of server-api. The `rules` table is
// evaluated by server-detect and never by this process, so a builtin that stops
// compiling removes that detection from the API server's pipeline outright —
// see docs/検知ルールの二重管理とデプロイ.md.
//
// The loader used to swallow the failure:
//
//	if err := e.LoadRule(yaml); err != nil {
//		_ = err // caller can ignore; counts are returned
//		continue
//	}
//
// Only the success count was returned, so the trace of a rule going dark was a
// smaller number in a startup log line. Nothing compares that number to
// anything. A detection can be removed from the product by a YAML typo and the
// only symptom is an alert that never fires — which is indistinguishable from
// an environment where the attack never happened.
//
// 302 of 302 load today, and this test is what says so.

func TestEveryBuiltinSigmaRuleLoads(t *testing.T) {
	if len(builtinSigmaRules) == 0 {
		t.Fatal("組み込みルールが1件もありません。走査が届いていません")
	}

	var failures []string
	for i, ruleYAML := range builtinSigmaRules {
		e := NewSigmaEvaluator()
		if err := e.LoadRule(ruleYAML); err != nil {
			failures = append(failures, fmt.Sprintf("%s (#%d): %v", builtinRuleTitle(ruleYAML), i, err))
		}
	}

	if len(failures) > 0 {
		t.Errorf("組み込みSigmaルールのうち %d 件が読み込めません。"+
			"読み込めないルールは検知に使われず、症状は「そのアラートが出ない」だけです:\n  %s",
			len(failures), strings.Join(failures, "\n  "))
	}
}

// And the loader must report the same number, or the contract above is checked
// against a path production does not take.
func TestLoadBuiltinRulesReportsEveryRule(t *testing.T) {
	e := NewSigmaEvaluator()
	loaded := LoadBuiltinRules(e)
	if loaded != len(builtinSigmaRules) {
		t.Errorf("LoadBuiltinRules が %d 件しか読み込んでいません (全 %d 件)",
			loaded, len(builtinSigmaRules))
	}
}

// The count must be of rules that loaded, not of rules it was handed.
//
// With the real list every rule loads, so `return loaded` and
// `return len(rules)` agree and the test above cannot separate them. Given a
// list containing something that cannot compile, only one of them is right.
func TestTheCountIsOfRulesThatLoadedNotRulesOffered(t *testing.T) {
	good := builtinSigmaRules[0]
	broken := "title: Broken\nthis is not: [valid: yaml"

	for _, tc := range []struct {
		name  string
		rules []string
		want  int
	}{
		{"すべて正しい", []string{good}, 1},
		{"1件が壊れている", []string{good, broken}, 1},
		{"すべて壊れている", []string{broken, broken}, 0},
	} {
		e := NewSigmaEvaluator()
		got, failures := loadSigmaRuleSet(e, tc.rules)
		if got != tc.want {
			t.Errorf("%s: %d 件と報告 (want %d)。読み込めた数を返さなければ、"+
				"落ちたルールの分だけ検知が消えたまま数字は満点になります",
				tc.name, got, tc.want)
		}
		if len(failures) != len(tc.rules)-tc.want {
			t.Errorf("%s: 失敗が %d 件 (want %d)。数だけ合っていても、"+
				"どのルールが落ちたか言えなければ直しようがありません",
				tc.name, len(failures), len(tc.rules)-tc.want)
		}
		for _, f := range failures {
			if !strings.Contains(f, "Broken") {
				t.Errorf("%s: 失敗の記述がルール名を含んでいません: %q", tc.name, f)
			}
		}
	}
}

// builtinRuleTitle is what names a failure in the log and above. If it stops
// finding titles, every failure report becomes "(title 不明)" and the operator
// has an index into a slice they cannot see.
func TestTheFailureReportCanNameTheRule(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"title: Suspicious PowerShell\nid: x\n", "Suspicious PowerShell"},
		{"\n  title:   Mimikatz  \nlogsource:\n", "Mimikatz"},
		{"id: x\nlogsource:\n", "(title 不明)"},
		{"", "(title 不明)"},
	} {
		if got := builtinRuleTitle(tc.in); got != tc.want {
			t.Errorf("builtinRuleTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// And it must find a title in the real rules, not just the synthetic ones.
	unnamed := 0
	for _, r := range builtinSigmaRules {
		if builtinRuleTitle(r) == "(title 不明)" {
			unnamed++
		}
	}
	if unnamed > 0 {
		t.Errorf("組み込みルール %d 件の title を取り出せません", unnamed)
	}
}
