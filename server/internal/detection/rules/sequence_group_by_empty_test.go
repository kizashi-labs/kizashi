package rules

import (
	"context"
	"testing"
)

// bruteForceSuccessRule is migration 338's shipped body: 6 auth failures then a login,
// within 10 minutes, from the SAME source_ip.
const bruteForceSuccessRule = `
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 6
stage_2: login
group_by: source_ip
`

func authEvent(action, srcIP string) map[string]interface{} {
	e := map[string]interface{}{
		"type": "auth", "agent_id": "host-1", "platform": "linux",
		"action": action,
	}
	if srcIP != "" {
		e["source_ip"] = srcIP
	}
	return e
}

// TestSequenceGroupByIgnoresEventsWithoutTheField pins the fix for a false
// positive measured at 12,599.96 /1000 hosts/day (21 alerts) in the 2026-08-04
// FP soak — the second-largest contributor to that gate breach.
//
// Migration 338 argues in its own comment that sudo/su failures land in the ""
// source_ip bucket while SSH logins carry a real IP, so the two cannot mix. That
// reasoning silently assumes every login is remote. On a workstation the login is
// local and has no source_ip either, so benign "typo, typo, …, then log in"
// sequences all landed in one shared "" bucket and tripped a brute-force alert.
// tests/fpsoak/profiles/{dev-machine,it-admin}.toml declare exactly that shape:
// login and failed auth blocks, neither with a `sources` list.
//
// The rule asserts a relationship between events "from the same source". With no
// source there is nothing to assert, so such events must not participate at all.
func TestSequenceGroupByIgnoresEventsWithoutTheField(t *testing.T) {
	t.Run("送信元不明の失敗と成功は相関しない", func(t *testing.T) {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{behavioralRule("bf", bruteForceSuccessRule)})

		var fired bool
		for i := 0; i < 6; i++ {
			m, err := e.Evaluate(context.Background(), authEvent("failed", ""))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			fired = fired || hasRule(m, "bf")
		}
		m, err := e.Evaluate(context.Background(), authEvent("login", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if fired || hasRule(m, "bf") {
			t.Error("source_ip の無いイベント同士が「同一送信元」として相関しました。" +
				"ローカルログインのタイプミスがブルートフォース成功として誤検知されます")
		}
	})

	t.Run("同一の実送信元からの連鎖は従来どおり検知する", func(t *testing.T) {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{behavioralRule("bf", bruteForceSuccessRule)})

		for i := 0; i < 6; i++ {
			if _, err := e.Evaluate(context.Background(), authEvent("failed", "203.0.113.9")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEvent("login", "203.0.113.9"))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(m, "bf") {
			t.Error("実際のブルートフォース成功（同一 IP から失敗6回→成功）が検知されませんでした。" +
				"空値の除外が広すぎて本来の検知まで消しています")
		}
	})

	t.Run("送信元が異なれば相関しない", func(t *testing.T) {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{behavioralRule("bf", bruteForceSuccessRule)})

		for i := 0; i < 6; i++ {
			if _, err := e.Evaluate(context.Background(), authEvent("failed", "203.0.113.9")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEvent("login", "10.0.0.5"))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(m, "bf") {
			t.Error("別の送信元からのログインが相関しました")
		}
	})

	// agent_id is the default partition and is always populated; excluding empty
	// values must not disturb the rules that rely on it.
	t.Run("group_by 未指定（agent_id 既定）は影響を受けない", func(t *testing.T) {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{behavioralRule("bf2", `
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 2
stage_2: login
`)})
		for i := 0; i < 2; i++ {
			if _, err := e.Evaluate(context.Background(), authEvent("failed", "")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEvent("login", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(m, "bf2") {
			t.Error("group_by 未指定のルールが発火しなくなりました（agent_id 既定の経路を壊しています）")
		}
	})
}
