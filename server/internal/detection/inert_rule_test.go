package detection

import (
	"strings"
	"testing"
)

// A rule that is enabled, listed, and cannot ever match.
//
// Conditions are ANDed (ruleMatchesEvent returns false on the first that does
// not match), so one condition that can never be true makes the whole rule
// silent. Two ways to write one, and neither said anything:
//
//	numericCompare("gt", got, want) — a rule written `cpu_percent > ninety`
//	fails ParseFloat on `want` and returns false. The same `return false` also
//	covers the healthy case where the *event's* value is not a number, so the
//	two were indistinguishable: one is a rule that does not apply to this
//	event, the other is a rule that applies to nothing.
//
//	compileRegexConditions — an invalid pattern leaves the compiled entry nil
//	and `re != nil && re.MatchString(got)` is false forever. This one did log,
//	once, at load.
//
// The Sigma side had the same shape: `|gt: ninety` was skipped inside the
// matcher with `continue`, so the comparison could not be true. That now fails
// at compile, which the loaders report by name.
//
// The symptom in every case is an alert that never fires, which looks exactly
// like an environment where the attack never happened.

func TestInertReasonsNamesRulesThatCannotFire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		conds []CustomRuleCondition
		want  int
		match string
	}{
		{
			name:  "数値比較の相手が文字列",
			conds: []CustomRuleCondition{{Field: "cpu_percent", Operator: "gt", Value: "ninety"}},
			want:  1, match: "数値ではありません",
		},
		{
			name:  "正規表現が不正",
			conds: []CustomRuleCondition{{Field: "image", Operator: "regex", Value: "([a-z"}},
			want:  1, match: "正規表現が不正",
		},
		{
			name:  "未対応の演算子",
			conds: []CustomRuleCondition{{Field: "image", Operator: "startswith", Value: "x"}},
			want:  1, match: "未対応の演算子",
		},
		{
			name: "壊れた条件が1つでもあればルール全体が鳴らない",
			conds: []CustomRuleCondition{
				{Field: "image", Operator: "contains", Value: "powershell"},
				{Field: "cpu_percent", Operator: "gte", Value: "high"},
			},
			want: 1, match: "cpu_percent",
		},
		{
			name: "正しいルールは何も報告しない",
			conds: []CustomRuleCondition{
				{Field: "image", Operator: "contains", Value: "powershell"},
				{Field: "cpu_percent", Operator: "gt", Value: "90"},
				{Field: "user", Operator: "regex", Value: "^adm.*"},
				{Field: "type", Operator: "eq", Value: "process_created"},
			},
			want: 0,
		},
		{
			name:  "小数と符号も数値",
			conds: []CustomRuleCondition{{Field: "score", Operator: "lte", Value: "-0.5"}},
			want:  0,
		},
		{
			name:  "空の演算子は文字列一致として扱う",
			conds: []CustomRuleCondition{{Field: "image", Operator: "", Value: "x"}},
			want:  0,
		},
	} {
		got := inertReasons(tc.conds)
		if len(got) != tc.want {
			t.Errorf("%s: %d件 (want %d): %v", tc.name, len(got), tc.want, got)
			continue
		}
		if tc.match != "" && !strings.Contains(strings.Join(got, " "), tc.match) {
			t.Errorf("%s: 理由が %q を含んでいません: %v", tc.name, tc.match, got)
		}
	}
}

// And the property the reasons are about: a rule inertReasons flags really
// cannot match, and one it passes really can. Without this the list could
// drift into naming things that are fine, or missing things that are not.
func TestAFlaggedRuleNeverMatchesAndACleanOneDoes(t *testing.T) {
	event := map[string]interface{}{
		"type":        "process_created",
		"image":       "powershell.exe",
		"cpu_percent": "95",
	}

	broken := CustomRule{
		Name: "broken", EventType: "process_created", ThresholdCount: 1,
		Conditions: []CustomRuleCondition{
			{Field: "image", Operator: "contains", Value: "powershell"},
			{Field: "cpu_percent", Operator: "gt", Value: "ninety"},
		},
	}
	broken.compiled = compileRegexConditions(broken.Name, broken.Conditions)
	if len(inertReasons(broken.Conditions)) == 0 {
		t.Fatal("壊れたルールが報告されていません")
	}
	if ruleMatchesEvent(broken, event) {
		t.Error("報告したルールが一致しました。報告が間違っています")
	}

	clean := broken
	clean.Name = "clean"
	clean.Conditions = []CustomRuleCondition{
		{Field: "image", Operator: "contains", Value: "powershell"},
		{Field: "cpu_percent", Operator: "gt", Value: "90"},
	}
	clean.compiled = compileRegexConditions(clean.Name, clean.Conditions)
	if len(inertReasons(clean.Conditions)) != 0 {
		t.Fatalf("正しいルールが報告されています: %v", inertReasons(clean.Conditions))
	}
	if !ruleMatchesEvent(clean, event) {
		t.Error("正しいルールが一致しません。この差が「鳴らない理由」の全体です")
	}
}

// The Sigma side. A numeric modifier with no numeric threshold must fail to
// load rather than compile into a matcher that cannot return true.
func TestSigmaRejectsANumericModifierWithNoNumber(t *testing.T) {
	const inert = `
title: Inert numeric rule
logsource:
  category: process_creation
detection:
  selection:
    cpu_percent|gt: ninety
  condition: selection
`
	e := NewSigmaEvaluator()
	err := e.LoadRule(inert)
	if err == nil {
		t.Fatal("数値でない閾値のルールが読み込まれました。" +
			"この条件は絶対に真にならないので、ルールは黙って鳴りません")
	}
	if !strings.Contains(err.Error(), "gt") {
		t.Errorf("エラーがどの修飾子か言っていません: %v", err)
	}

	const good = `
title: Working numeric rule
logsource:
  category: process_creation
detection:
  selection:
    cpu_percent|gt: 90
  condition: selection
`
	if err := NewSigmaEvaluator().LoadRule(good); err != nil {
		t.Errorf("正しいルールが読み込めません: %v", err)
	}
}

// One unparseable threshold among several is not inert — the others still give
// the comparison meaning — so it must not be rejected.
func TestSigmaKeepsARuleWithAtLeastOneNumericThreshold(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
		wantErr  bool
		wantMsg  string
	}{
		{"すべて数値", []string{"90", "95"}, false, ""},
		{"一部が数値でない", []string{"ninety", "95"}, false, ""},
		{"すべて数値でない", []string{"ninety", "high"}, true, "no numeric threshold"},
		{"閾値が無い", nil, true, "has no threshold"},
	} {
		err := requireNumericThresholds("gt", tc.patterns)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", tc.name, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("%s: エラーが %q を含んでいません: %v", tc.name, tc.wantMsg, err)
		}
	}
}

// 読み込んだルール群から「絶対に鳴らないもの」を集める部分。
// 読み込みループはデータベースが要るので、集計だけを直接動かします。
func TestInertRulesCollectsByName(t *testing.T) {
	rules := []CustomRule{
		{Name: "ok", Conditions: []CustomRuleCondition{{Field: "image", Operator: "contains", Value: "x"}}},
		{Name: "bad-number", Conditions: []CustomRuleCondition{{Field: "cpu", Operator: "gt", Value: "ninety"}}},
		{Name: "bad-regex", Conditions: []CustomRuleCondition{{Field: "image", Operator: "regex", Value: "([a-z"}}},
		{Name: "two-reasons", Conditions: []CustomRuleCondition{
			{Field: "cpu", Operator: "gt", Value: "high"},
			{Field: "image", Operator: "regex", Value: "([a-z"},
		}},
	}
	got := inertRules(rules)
	if len(got) != 3 {
		t.Fatalf("%d件 (want 3): %v", len(got), got)
	}
	if _, ok := got["ok"]; ok {
		t.Error("正しいルールが「鳴らない」に入っています")
	}
	if !strings.Contains(got["two-reasons"], ";") {
		t.Errorf("理由が2つとも入っていません: %q", got["two-reasons"])
	}
	if len(inertRules(nil)) != 0 {
		t.Error("ルールが無いのに何か報告されています")
	}
}

// InertRules() は、いま載っているルールから求まること。控えた写しを返して
// いると、ルールを入れ替えたあとも古い一覧が返り続けます。
func TestInertRulesFollowsTheLoadedRules(t *testing.T) {
	e := NewCustomRuleEvaluator()
	if len(e.InertRules()) != 0 {
		t.Fatal("ルールを入れる前から何か報告されています")
	}

	e.mu.Lock()
	e.rules = []CustomRule{
		{Name: "bad", Conditions: []CustomRuleCondition{{Field: "cpu", Operator: "gt", Value: "ninety"}}},
	}
	e.mu.Unlock()
	if got := e.InertRules(); len(got) != 1 || !strings.Contains(got["bad"], "数値") {
		t.Errorf("鳴らないルールが報告されていません: %v", got)
	}

	e.mu.Lock()
	e.rules = []CustomRule{
		{Name: "good", Conditions: []CustomRuleCondition{{Field: "cpu", Operator: "gt", Value: "90"}}},
	}
	e.mu.Unlock()
	if got := e.InertRules(); len(got) != 0 {
		t.Errorf("直したあとも古い報告が残っています: %v", got)
	}
}
