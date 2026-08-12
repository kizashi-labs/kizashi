package rules

import "testing"

// These tests guard the field-name contract for auth brute-force rules
// (migration 288). The normalized auth event emitted by ingestion uses the
// fields {username, action, success, source_ip, auth_method, failure_reason}
// with action=="failed" for a failed logon — NOT eventName/4625/ssh_auth_fail.
// A rule referencing a field the telemetry never emits is silently inert, which
// is exactly the bug 288 fixes; these tests fail loudly if it regresses.

func authRule(id, content string) *DetectionRule {
	return &DetectionRule{ID: id, Name: id, Type: "behavioral", Enabled: true, Severity: 7, Content: content}
}

func observeAuthFailed(se *SequenceEngine, agent, username, srcIP string) []*RuleMatch {
	return se.Observe(agent, "auth", map[string]any{
		"action":    "failed",
		"success":   false,
		"username":  username,
		"source_ip": srcIP,
	})
}

// Targeted brute force: N failures for the same username must fire.
func TestAuthBruteForce_PerUsername_Fires(t *testing.T) {
	const content = `
window: 120s
threshold: 8
event_type: auth
field: action
value: failed
group_by: username`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{authRule("bf", content)})

	var last []*RuleMatch
	for range 8 {
		last = observeAuthFailed(se, "agent-1", "administrator", "10.0.0.5")
	}
	if len(last) == 0 {
		t.Fatal("8回の連続認証失敗(同一ユーザー)でブルートフォースルールが発火しませんでした" +
			" — field:action/value:failed の契約が壊れている可能性")
	}
}

// The old broken content (field: eventName / value: 4625) must NOT fire — this
// documents why 288 was needed: the field does not exist on the event.
func TestAuthBruteForce_BrokenFieldName_NeverFires(t *testing.T) {
	const broken = `
window: 120s
threshold: 3
event_type: auth
field: eventName
value: 4625
group_by: agent_id`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{authRule("bf-broken", broken)})

	var last []*RuleMatch
	for range 10 {
		last = observeAuthFailed(se, "agent-1", "administrator", "10.0.0.5")
	}
	if len(last) != 0 {
		t.Fatal("eventName フィールドは正規化イベントに存在しないため発火してはいけない")
	}
}

// Password spray: distinct usernames from one source must fire.
func TestAuthPasswordSpray_DistinctUsernames_Fires(t *testing.T) {
	const content = `
window: 300s
threshold: 5
event_type: auth
field: action
value: failed
group_by: source_ip
distinct: true
distinct_field: username`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{authRule("spray", content)})

	users := []string{"alice", "bob", "carol", "dave", "erin"}
	var last []*RuleMatch
	for _, u := range users {
		last = observeAuthFailed(se, "agent-1", u, "203.0.113.9") // same source
	}
	if len(last) == 0 {
		t.Fatal("同一送信元から5種類の異なるユーザー名への失敗でスプレールールが発火しませんでした")
	}
}

// Password spray must NOT fire when the SAME username fails repeatedly from one
// source (that is targeted brute force, a distinct signal — spray counts distinct users).
func TestAuthPasswordSpray_SameUsername_NoFire(t *testing.T) {
	const content = `
window: 300s
threshold: 5
event_type: auth
field: action
value: failed
group_by: source_ip
distinct: true
distinct_field: username`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{authRule("spray", content)})

	var last []*RuleMatch
	for range 10 {
		last = observeAuthFailed(se, "agent-1", "administrator", "203.0.113.9")
	}
	if len(last) != 0 {
		t.Fatal("同一ユーザーの反復失敗はスプレー(distinct users)では発火してはいけない")
	}
}
