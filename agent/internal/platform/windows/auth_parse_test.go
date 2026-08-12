// auth_parse_test.go — ビルドタグ無し。auth_collector.go は windows タグ配下で
// Linux CI から一度もコンパイルされないため、そこに置かれていた変換ロジックは
// 実機に出るまで誰にも検証されなかった。ここに移したことで CI が守れる。

package windows

import "testing"

// eventXML builds a Security-log record in the shape EvtRender produces
// (default namespace, single-quoted, EventData as named Data elements).
func eventXML(eventID string, data map[string]string) string {
	s := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
		`<EventID>` + eventID + `</EventID>` +
		`<TimeCreated SystemTime='2026-08-05T09:33:53.000000000Z'/>` +
		`</System><EventData>`
	for k, v := range data {
		s += `<Data Name='` + k + `'>` + v + `</Data>`
	}
	return s + `</EventData></Event>`
}

// A failed logon must be reported as a failure. This is the only input that feeds
// AuthAttackScorer's brute-force and password-spray counters (T1110).
func TestParseAuthEvent_FailedLogon(t *testing.T) {
	evt, err := parseAuthEvent(eventXML("4625", map[string]string{
		"TargetUserName": "edr-t1110-1",
		"IpAddress":      "10.0.0.9",
		"LogonType":      "3",
		"SubStatus":      "0xC0000064",
	}))
	if err != nil {
		t.Fatalf("parseAuthEvent: %v", err)
	}
	if evt.Action != "failed" || evt.Success {
		t.Errorf("4625 → action=%q success=%v, want action=\"failed\" success=false",
			evt.Action, evt.Success)
	}
	if evt.Username != "edr-t1110-1" {
		t.Errorf("username = %q, want the TargetUserName", evt.Username)
	}
}

// ★ The regression this file exists for.
//
// 4648 records that a process SUPPLIED credentials; it says nothing about the
// outcome. It used to be mapped to Action="login", Success=true, which fabricated
// logins that never happened: PrincipalContext.ValidateCredentials emits 4625 AND
// 4648 for one failed attempt, so AuthAttackScorer read "many failures, then a
// success" and raised a severity-8 "account compromised" alert — on the validation
// host, against accounts that do not exist (2026-08-05).
//
// It must not parse into a successful login. Dropping it entirely is the current
// contract; if it is ever reinstated it needs an outcome-neutral representation
// AND a matching skip in AuthAttackScorer, so this test should be updated
// deliberately, never just deleted.
func TestParseAuthEvent_ExplicitCredentialsIsNotASuccessfulLogin(t *testing.T) {
	evt, err := parseAuthEvent(eventXML("4648", map[string]string{
		"TargetUserName":  "edr-t1110-1",
		"SubjectUserName": "Administrator",
		"IpAddress":       "10.0.0.9",
	}))
	if err == nil && evt.Success {
		t.Fatalf("4648 が成功ログオンとして解釈されました (action=%q success=%v)。"+
			"これは失敗ログオンから偽の「アカウント侵害」アラートを生みます",
			evt.Action, evt.Success)
	}
}

func TestParseAuthEvent_SuccessfulLogon(t *testing.T) {
	evt, err := parseAuthEvent(eventXML("4624", map[string]string{
		"TargetUserName": "alice",
		"IpAddress":      "10.0.0.9",
		"LogonType":      "10",
	}))
	if err != nil {
		t.Fatalf("parseAuthEvent: %v", err)
	}
	if evt.Action != "login" || !evt.Success {
		t.Errorf("4624 → action=%q success=%v, want action=\"login\" success=true",
			evt.Action, evt.Success)
	}
	if evt.AuthMethod != "remote_interactive" {
		t.Errorf("LogonType 10 → %q, want \"remote_interactive\"", evt.AuthMethod)
	}
}

// High-frequency service accounts are dropped on purpose: they would swamp the
// rate detectors with events no analyst acts on.
func TestParseAuthEvent_SkipsSystemAccounts(t *testing.T) {
	for _, u := range []string{"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-", ""} {
		if _, err := parseAuthEvent(eventXML("4624", map[string]string{
			"TargetUserName": u,
		})); err == nil {
			t.Errorf("システムアカウント %q が除外されませんでした", u)
		}
	}
}

// An event ID outside the collected set must be rejected rather than silently
// mapped onto some default action.
func TestParseAuthEvent_RejectsUncollectedEventIDs(t *testing.T) {
	for _, id := range []string{"4648", "4776", "1102"} {
		if _, err := parseAuthEvent(eventXML(id, map[string]string{
			"TargetUserName": "alice",
		})); err == nil {
			t.Errorf("収集対象外の EventID %s が受理されました", id)
		}
	}
}

// The subscription/poll query must not fetch 4648 at all — not fetching it is what
// makes a parsing mistake impossible in the first place.
func TestAuthQueryDoesNotSelect4648(t *testing.T) {
	for _, q := range []string{buildAuthSubscribeQuery(), buildAuthQuery(60000)} {
		if contains(q, "4648") {
			t.Errorf("クエリが 4648 を選択しています: %s", q)
		}
		for _, want := range []string{"4624", "4625", "4634", "4672"} {
			if !contains(q, want) {
				t.Errorf("クエリに %s がありません: %s", want, q)
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
