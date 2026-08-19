package rules

import (
	"errors"
	"strings"
	"testing"
)

// A behavioral rule that meant to be a sequence rule and is not quite one.
//
// LoadRules did this:
//
//	sr, err := parseSequenceRule(r)
//	if err != nil {
//		continue // not a sequence rule (plain key:value behavioral rule)
//	}
//
// The comment is true of one error and false of the rest. parseSequenceRule
// returns "not a sequence rule" for a plain behavioral rule — correctly
// skipped — and also returns "invalid window '5x'", "invalid threshold
// 'three'" and "staged rule needs at least 2 stages" for a rule whose author
// wrote window: and threshold:, meant a kill chain, and mistyped one
// character. Those were dropped here without a word.
//
// An operator writes a rule, enables it, sees it listed, and it never fires.
// There is no log line, no count, and no screen that would show it. The
// symptom is identical to "the attack did not happen".
//
// The other direction was worse. `stages: process_created` — a single stage
// where the format wants two — parsed to zero stages, so the guard
// `len(stages) > 0 && len(stages) < 2` did not fire, and with no explicit
// threshold the rule took threshold = len(stages) = 0. A threshold of zero is
// satisfied before any event arrives, so a kill-chain rule became an alert on
// the first process creation it saw. Measured, not reasoned about: the rule
// loaded and Observe returned a match on event 1.

func loadOne(t *testing.T, content string) *SequenceEngine {
	t.Helper()
	e := NewSequenceEngine()
	e.LoadRules([]*DetectionRule{{
		ID: "r1", Name: "r1", Type: "behavioral", Enabled: true, Content: content,
	}})
	return e
}

// The headline: a malformed sequence rule is reported, not silently dropped.
func TestAMalformedSequenceRuleIsCounted(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"window の書式違い", "window: 5x\nthreshold: 3\nevent_type: process_created"},
		{"threshold が数値でない", "window: 5m\nthreshold: three\nevent_type: process_created"},
		{"threshold がゼロ", "window: 5m\nthreshold: 0\nevent_type: process_created"},
		{"stages が1つしかない", "window: 5m\nstages: process_created"},
		{"stages が空", "window: 5m\nstages: \nthreshold: 2"},
	} {
		e := loadOne(t, tc.content)
		if len(e.rules) != 0 {
			t.Errorf("%s: 壊れたルールが読み込まれています (threshold=%d, stages=%d)",
				tc.name, e.rules[0].threshold, len(e.rules[0].stages))
		}
		if e.Malformed() != 1 {
			t.Errorf("%s: malformed=%d, want 1。黙って捨てると、"+
				"書いた人はルールが動いていると思い続けます", tc.name, e.Malformed())
		}
	}
}

// A plain behavioral rule is not malformed; it belongs to another evaluator.
// Counting it would make the number meaningless and train people to ignore it.
func TestAPlainBehavioralRuleIsNotCountedAsMalformed(t *testing.T) {
	for _, content := range []string{
		"event_type: process_created",
		"field: image\nvalue: powershell.exe",
		"threshold: 3", // no window: not a sequence rule
	} {
		e := loadOne(t, content)
		if e.Malformed() != 0 {
			t.Errorf("%q が malformed に数えられています", content)
		}
	}
}

// A correct rule still loads, and with the values it was given.
func TestAWellFormedSequenceRuleStillLoads(t *testing.T) {
	e := loadOne(t, "window: 5m\nthreshold: 3\nevent_type: process_created")
	if len(e.rules) != 1 {
		t.Fatalf("正しいルールが読み込まれていません (malformed=%d)", e.Malformed())
	}
	if e.rules[0].threshold != 3 {
		t.Errorf("threshold = %d, want 3", e.rules[0].threshold)
	}
	if e.Malformed() != 0 {
		t.Errorf("malformed = %d, want 0", e.Malformed())
	}
}

// The two error kinds must stay distinguishable. If errNotSequenceRule stops
// being returned for plain rules, every plain behavioral rule is reported as
// broken; if it starts being returned for malformed ones, nothing is.
func TestTheTwoErrorKindsAreDistinguishable(t *testing.T) {
	plain := &DetectionRule{ID: "p", Name: "p", Content: "event_type: process_created"}
	if _, err := parseSequenceRule(plain); !errors.Is(err, errNotSequenceRule) {
		t.Errorf("素の behavioral ルールが errNotSequenceRule を返していません: %v", err)
	}

	broken := &DetectionRule{ID: "b", Name: "b", Content: "window: 5x\nthreshold: 3"}
	_, err := parseSequenceRule(broken)
	if err == nil {
		t.Fatal("壊れたルールがエラーを返していません")
	}
	if errors.Is(err, errNotSequenceRule) {
		t.Error("壊れたルールが「シーケンスルールではない」として扱われています")
	}
	if !strings.Contains(err.Error(), "5x") {
		t.Errorf("エラーがどこが悪いのか言っていません: %v", err)
	}
}

// No rule may reach the matcher with a threshold that is already satisfied.
// This is the one that fired on the first event.
func TestNoLoadedRuleMatchesBeforeAnyEvent(t *testing.T) {
	e := NewSequenceEngine()
	e.LoadRules([]*DetectionRule{
		{ID: "a", Name: "staged typo", Type: "behavioral", Enabled: true,
			Content: "window: 5m\nstages: process_created"},
		{ID: "b", Name: "good", Type: "behavioral", Enabled: true,
			Content: "window: 5m\nthreshold: 3\nevent_type: process_created"},
	})
	for _, r := range e.rules {
		if r.threshold < 1 {
			t.Fatalf("ルール %q の threshold が %d です。イベントが1件も来る前に成立します",
				r.rule.Name, r.threshold)
		}
	}

	// And the behaviour, not just the field: one event must not be a match for
	// a rule that asked for a sequence.
	m := e.Observe("agent-1", "process_created", map[string]any{
		"event_type": "process_created", "image": "x.exe",
	})
	if len(m) != 0 {
		t.Errorf("最初の1件で %d 件マッチしました。シーケンスルールは1件では成立しません", len(m))
	}
}
