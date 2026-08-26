package rules

import (
	"context"
	"testing"
)

// bruteForceExpiryRule is migration 372's shipped body for rule 338: 6 auth
// failures then a login, within 10 minutes, from the same source_ip — with
// password-expiry failures excluded from the failure count.
const bruteForceExpiryRule = `
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 6
stage_1_exclude_field: failure_reason
stage_1_exclude: password has expired, password must be changed, password expired
stage_2: login
group_by: source_ip
`

func authEventWithReason(action, srcIP, reason string) map[string]interface{} {
	e := map[string]interface{}{
		"type": "auth", "agent_id": "host-1", "platform": "linux",
		"action": action,
	}
	if srcIP != "" {
		e["source_ip"] = srcIP
	}
	if reason != "" {
		e["failure_reason"] = reason
	}
	return e
}

// TestStageExcludeDropsPasswordExpiryFailures pins the discriminator behind
// migration 372.
//
// A failure whose reason is "password has expired" or "password must be changed"
// is not a guess: those responses are only produced when the submitted password
// was CORRECT and the account state blocks the login. An attacker guessing
// passwords never sees them — by the time the password is right, the guessing is
// over. Counting them turned ordinary password-expiry clusters into brute-force
// alerts: the FP soak measured 9,599.96 /1000 hosts/day across 7 hosts, sourced
// from the file-server and it-admin profiles whose benign auth failures carry
// exactly these reasons.
//
// The exclusion must not weaken what the rule still detects, so the second case
// asserts that ordinary wrong-password failures still correlate.
func TestStageExcludeDropsPasswordExpiryFailures(t *testing.T) {
	newEngine := func() *RuleEngine {
		e := NewRuleEngine()
		e.LoadRules([]*DetectionRule{behavioralRule("bf", bruteForceExpiryRule)})
		return e
	}

	t.Run("期限切れの失敗は数えない", func(t *testing.T) {
		e := newEngine()
		for i := 0; i < 8; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "10.20.1.12",
					"The user's password must be changed before signing in")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEventWithReason("login", "10.20.1.12", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(m, "bf") {
			t.Error("パスワード期限切れの失敗をブルートフォースとして数えました。" +
				"これらは提出したパスワードが正しかった場合にのみ返る応答で、" +
				"推測攻撃では発生しません")
		}
	})

	t.Run("通常の認証失敗は従来どおり検知する", func(t *testing.T) {
		e := newEngine()
		for i := 0; i < 6; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "203.0.113.9", "Authentication failure")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEventWithReason("login", "203.0.113.9", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(m, "bf") {
			t.Error("通常の認証失敗6回→成功が検知されませんでした。除外が広すぎます")
		}
	})

	// The reason field is optional across producers. Dropping events that simply
	// lack it would disable the stage for every source that does not populate it.
	t.Run("failure_reason が無いイベントは従来どおり数える", func(t *testing.T) {
		e := newEngine()
		for i := 0; i < 6; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "203.0.113.9", "")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEventWithReason("login", "203.0.113.9", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(m, "bf") {
			t.Error("failure_reason を持たない失敗が数えられなくなりました。" +
				"この列を埋めないプロデューサで段が黙って無効になります")
		}
	})

	// A real attack against an account that later expires still has to be caught:
	// the expiry failures are dropped, the guesses are not.
	t.Run("期限切れが混ざっても本物の推測は数える", func(t *testing.T) {
		e := newEngine()
		for i := 0; i < 3; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "203.0.113.9",
					"The specified account password has expired")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		for i := 0; i < 6; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "203.0.113.9", "Authentication failure")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEventWithReason("login", "203.0.113.9", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(m, "bf") {
			t.Error("期限切れの失敗が混ざると本物の推測まで数えられなくなりました")
		}
	})

	t.Run("大文字小文字を無視して除外する", func(t *testing.T) {
		e := newEngine()
		for i := 0; i < 8; i++ {
			if _, err := e.Evaluate(context.Background(),
				authEventWithReason("failed", "10.20.1.12",
					"The Specified Account PASSWORD HAS EXPIRED")); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
		}
		m, err := e.Evaluate(context.Background(), authEventWithReason("login", "10.20.1.12", ""))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(m, "bf") {
			t.Error("除外が大文字小文字に依存しています")
		}
	})
}
