// auth_parse_test.go — Security イベント XML → AuthEvent の変換テスト。
// auth_query_test.go と同じくビルドタグ無しで、Linux の CI でも実行される。

package windows

import (
	"strings"
	"testing"
)

// A Kerberos service-ticket request (4769) carries the whole Kerberoasting
// signal, and AuthEvent carried none of it: username, action, success,
// source_ip, auth_method, failure_reason and logon_type were the entire
// message. So ldap.DetectKerberoasting — which keys on target_spn,
// ticket_encryption_type and event_id — matched nothing on any deployment.
//
// The parser is the only place this can be checked without a Windows host,
// which is why it lives in an untagged file.

const kerb4769XML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4769</EventID>
    <TimeCreated SystemTime='2026-08-05T09:00:00.000000000Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>alice@CORP.LOCAL</Data>
    <Data Name='ServiceName'>MSSQLSvc/db01.corp.local:1433</Data>
    <Data Name='TicketEncryptionType'>0x17</Data>
    <Data Name='IpAddress'>10.1.2.3</Data>
    <Data Name='Status'>0x0</Data>
  </EventData>
</Event>`

// The headline: an RC4 service-ticket request becomes an AuthEvent carrying the
// three fields the detection needs.
func TestParse4769CarriesTheKerberosFields(t *testing.T) {
	evt, err := parseAuthEvent(kerb4769XML)
	if err != nil {
		t.Fatalf("parseAuthEvent: %v", err)
	}
	if evt.EventID != 4769 {
		t.Errorf("EventID = %d, want 4769", evt.EventID)
	}
	if evt.TargetSPN != "MSSQLSvc/db01.corp.local:1433" {
		t.Errorf("TargetSPN = %q。Kerberoasting 検知は SPN で判定します", evt.TargetSPN)
	}
	if evt.TicketEncryptionType != "0x17" {
		t.Errorf("TicketEncryptionType = %q, want 0x17", evt.TicketEncryptionType)
	}
	if evt.AuthMethod != "kerberos" {
		t.Errorf("AuthMethod = %q, want kerberos", evt.AuthMethod)
	}
	if evt.Action != "kerberos_service_ticket" {
		t.Errorf("Action = %q。サービスチケット要求はログオンではありません", evt.Action)
	}
	// 4769 has no WorkstationName, so the source must come from IpAddress.
	if evt.SourceIP != "10.1.2.3" {
		t.Errorf("SourceIP = %q, want 10.1.2.3", evt.SourceIP)
	}
	if evt.Username != "alice@CORP.LOCAL" {
		t.Errorf("Username = %q", evt.Username)
	}
}

// An AES ticket is the ordinary case and is dropped at the endpoint. 4769 is
// logged per service-ticket by the domain controller, so forwarding all of it
// would be thousands of events per second of routine domain traffic.
func TestParse4769DropsTheRoutineTraffic(t *testing.T) {
	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"AES ticket", strings.Replace(kerb4769XML, "0x17", "0x12", 1)},
		{"machine account", strings.Replace(kerb4769XML, "alice@CORP.LOCAL", "WKSTN01$@CORP.LOCAL", 1)},
		{"machine service", strings.Replace(kerb4769XML, "MSSQLSvc/db01.corp.local:1433", "DC01$", 1)},
	} {
		if _, err := parseAuthEvent(tc.xml); err == nil {
			t.Errorf("%s: 転送対象として扱われました。"+
				"ドメインコントローラの通常トラフィックをそのまま取り込むことになります",
				tc.name)
		}
	}
}

// Every other auth event must still parse, and must carry its event ID — the
// password-spray detection reads it.
func TestParseOrdinaryLogonStillWorksAndCarriesItsEventID(t *testing.T) {
	const failed = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime='2026-08-05T09:00:00.000000000Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>bob</Data>
    <Data Name='IpAddress'>10.9.9.9</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='FailureReason'>%%2313</Data>
  </EventData>
</Event>`

	evt, err := parseAuthEvent(failed)
	if err != nil {
		t.Fatalf("parseAuthEvent: %v", err)
	}
	if evt.EventID != 4625 {
		t.Errorf("EventID = %d, want 4625", evt.EventID)
	}
	if evt.Success {
		t.Error("4625 を成功として扱っています")
	}
	if evt.Username != "bob" || evt.SourceIP != "10.9.9.9" {
		t.Errorf("既存フィールドが壊れました: user=%q ip=%q", evt.Username, evt.SourceIP)
	}
	// And it must not be mistaken for a Kerberos event.
	if evt.TargetSPN != "" || evt.TicketEncryptionType != "" {
		t.Errorf("通常のログオンに Kerberos フィールドが入っています: spn=%q enc=%q",
			evt.TargetSPN, evt.TicketEncryptionType)
	}
}

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

// ── T1134.005: SID-History の付与 (4765/4766) ──
//
// 2026-08-14 に購読と変換を通した。それまでこの 2 つは default 分岐で捨てられて
// おり、**サーバ側でどれだけルールを書いても検知できない**状態だった。
// 「フィールド解決の検査は通るが値が永久に来ない」という最も見つけにくい形なので、
// 供給側をここで固定する。
func TestParseAuthEvent_SIDHistoryAdded(t *testing.T) {
	evt, err := parseAuthEvent(eventXML("4765", map[string]string{
		"TargetUserName":  "svc-backup",
		"SubjectUserName": "admin",
	}))
	if err != nil {
		t.Fatalf("4765 が捨てられている（これが検知の入口）: %v", err)
	}
	if evt.EventID != 4765 {
		t.Errorf("EventID = %d, want 4765。ワイヤに乗らないとサーバ側で区別が付かない", evt.EventID)
	}
	// **付与された側**を主体として記録する。SubjectUserName は付与した側。
	if evt.Username != "svc-backup" {
		t.Errorf("username = %q, want the TargetUserName (SID-History を付与された側)", evt.Username)
	}
	if !evt.Success {
		t.Error("4765 は付与の成功なので Success=true であるべき")
	}
	// ★ 失敗として数えられてはならない。4648 を取り込んで偽の「アカウント侵害」
	// アラートを捏造した 2026-08-05 の事故と同じ形になる。
	if evt.Action == "failed" {
		t.Error("action=\"failed\" にしてはならない: AuthAttackScorer の失敗カウンタに入る")
	}
}

func TestParseAuthEvent_SIDHistoryAddFailed(t *testing.T) {
	evt, err := parseAuthEvent(eventXML("4766", map[string]string{
		"TargetUserName": "svc-backup",
	}))
	if err != nil {
		t.Fatalf("4766 が捨てられている: %v", err)
	}
	if evt.EventID != 4766 {
		t.Errorf("EventID = %d, want 4766", evt.EventID)
	}
	if evt.Success {
		t.Error("4766 は付与の失敗なので Success=false であるべき")
	}
	// success=false を持つので、action まで "failed" にするとブルートフォース検知器に
	// 二重に効く。サーバ側 (engine.go の isAccountManagementAuth) が除外する前提で、
	// action はログオンの語彙を使わない。
	if evt.Action == "failed" {
		t.Error("action=\"failed\" にしてはならない: ログオン失敗と区別が付かなくなる")
	}
}

// ログオン系にも EventID が乗ること。ワイヤは起きたことをそのまま書く——
// どの EventID を Sigma に露出するかはサーバ側の許可リストで決める
// (server/internal/detection/auth_attack.go の sigmaExposedAuthEventIDs)。
func TestParseAuthEvent_CarriesEventIDForLogons(t *testing.T) {
	for _, id := range []string{"4624", "4625", "4634", "4672"} {
		evt, err := parseAuthEvent(eventXML(id, map[string]string{
			"TargetUserName": "tanaka",
			"LogonType":      "3",
		}))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if evt.EventID == 0 {
			t.Errorf("%s の EventID が 0 のまま——ワイヤに乗っていない", id)
		}
	}
}
