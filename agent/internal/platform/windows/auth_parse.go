// auth_parse.go — Security チャネルのイベント XML を AuthEvent に変換する純粋関数。
//
// auth_query.go と同じ理由でビルドタグを付けていない。ここは syscall を一切
// 呼ばず、XML 文字列を構造体に変換するだけなので、Linux の CI でも実行できる。
// 収集経路そのものは windows タグ配下にあり CI では動かないため、フィールドの
// 取り違え — 実機で判明した「認証イベント0件」も、Kerberos フィールドが
// 一つも無かったことも、どちらもこの形の欠陥だった — を捕まえられる唯一の
// 場所がここになる。
// auth_parse.go — Security イベント XML を AuthEvent へ変換する純粋処理。
//
// auth_query.go と同じ理由でビルドタグを付けていない。auth_collector.go は windows
// タグ配下にあり Linux CI から一度もコンパイルもテストもされないため、そこに置いた
// 変換ロジックの誤りは実機に出るまで誰にも見えない。2026-08-05 の実機計測で、
// 4648(明示的資格情報でのログオン**試行**)を「ログオン成功」として扱っていたことが
// 判明した——存在しないアカウントへの失敗ログオンから severity 8 の
// 「ブルートフォース成功＝アカウント侵害」アラートが捏造されていた。
// syscall を含まない変換部分をここに置けば、どのプラットフォームの CI でも回帰を止められる。

package windows

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// winEventXML is a minimal representation of a Windows Event Log XML record.
type winEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID     uint32 `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseAuthEvent parses a Windows event XML string into an AuthEvent.
func parseAuthEvent(xmlStr string) (collector.AuthEvent, error) {
	// Strip the default namespace so Go's xml package matches element names simply.
	xmlStr = strings.Replace(xmlStr,
		` xmlns='http://schemas.microsoft.com/win/2004/08/events/event'`, "", 1)

	var raw winEventXML
	if err := xml.Unmarshal([]byte(xmlStr), &raw); err != nil {
		return collector.AuthEvent{}, fmt.Errorf("xml parse: %w", err)
	}

	ts, err := time.Parse("2006-01-02T15:04:05.000000000Z", raw.System.TimeCreated.SystemTime)
	if err != nil {
		ts, err = time.Parse("2006-01-02T15:04:05Z", raw.System.TimeCreated.SystemTime)
		if err != nil {
			ts = time.Now()
		}
	}

	// Build a name→value lookup from EventData.
	data := make(map[string]string, len(raw.EventData.Data))
	for _, d := range raw.EventData.Data {
		data[d.Name] = d.Value
	}

	evt := collector.AuthEvent{
		ID:        uuid.New().String(),
		Timestamp: ts,
		Username:  authFirstNonEmpty(data["TargetUserName"], data["SubjectUserName"]),
		SourceIP:  authFirstNonEmpty(data["IpAddress"], data["WorkstationName"]),
		// Raw Windows LogonType (3=Network, 10=RemoteInteractive/RDP, ...). Present
		// on 4624/4625; "" for events that don't carry it. Feeds the off-hours-login
		// UEBA feature and Sigma 4624/4625 LogonType rules (T1078).
		LogonType: data["LogonType"],
		// Raw Security-log event id. Until 2026-08-14 this was dropped, and the
		// comment below on 4648 recorded the consequence: "auth events carry no
		// EventID field". Account-manipulation events (4765/4766) are
		// indistinguishable from one another and from a privilege grant without
		// it, so SID-History could not be detected at all.
		//
		// Carried for every handled id, not just the new ones — the wire should
		// describe what happened. Which ids the Sigma layer is allowed to match on
		// is a separate decision, made in the server's alias layer
		// (addPipelineSigmaAliases), because exposing 4624/4625 to the
		// curate-enabled `service: security` rule corpus is an unmeasured change
		// in alert volume.
		EventID: raw.System.EventID,
	}

	switch raw.System.EventID {
	case 4624: // Successful logon
		evt.Action = "login"
		evt.Success = true
		evt.AuthMethod = logonTypeToMethod(data["LogonType"])
	case 4625: // Failed logon
		evt.Action = "failed"
		evt.Success = false
		evt.FailReason = authFirstNonEmpty(data["FailureReason"], data["SubStatus"])
	case 4634: // Logoff
		evt.Action = "logout"
		evt.Success = true
	case 4672: // Special privileges assigned (privilege escalation)
		evt.Action = "privilege"
		evt.Success = true
		evt.Username = authFirstNonEmpty(data["SubjectUserName"], data["TargetUserName"])
	case 4769: // Kerberos service ticket requested (TGS-REQ)
		// Only the tickets Kerberoasting produces are forwarded — a weak cipher,
		// a real account, a real service. 4769 is per-service-ticket on a domain
		// controller, so the unfiltered stream is thousands per second of a
		// workstation fetching a ticket for a file share. See
		// collector.KerberoastableTicket for the full reasoning and for what
		// this deliberately does not send.
		if !collector.KerberoastableTicket(
			data["TargetUserName"], data["ServiceName"], data["TicketEncryptionType"]) {
			return collector.AuthEvent{}, fmt.Errorf("4769 not kerberoastable")
		}
		evt.Action = "kerberos_service_ticket"
		evt.Success = data["Status"] == "" || data["Status"] == "0x0"
		evt.AuthMethod = "kerberos"
		evt.TargetSPN = data["ServiceName"]
		evt.TicketEncryptionType = data["TicketEncryptionType"]
		evt.Username = data["TargetUserName"]
		// 4769 puts the requesting host in IpAddress; there is no
		// WorkstationName on this event, so the generic fallback above may have
		// left it empty.
		evt.SourceIP = data["IpAddress"]
	case 4765, 4766: // SID History added to an account / attempt failed (T1134.005)
		// これはログオンではなくアカウント操作である。Action を "failed" にしては
		// **ならない**——AuthAttackScorer の失敗カウンタに入り、ブルートフォースの
		// 誤検知になる。4648 で実際に起きた形と同じである。
		//
		// Success は素直に成否を写すが、それだけでは engine.go 側の
		// authSucceeded() が `success: false` を失敗として数えてしまうため、
		// 呼び出し側でアカウント操作イベントを除外している(engine.go)。
		// 4648 のコメントが「復活させるなら AuthAttackScorer 側の除外もセットで
		// 要る」と書いていたとおりの手順である。
		evt.Action = "privilege"
		evt.Success = raw.System.EventID == 4765
		// TargetUserName は SID-History を**付与された**アカウント、
		// SubjectUserName は付与した側。狙われた側を主体として記録する。
		evt.Username = authFirstNonEmpty(data["TargetUserName"], data["SubjectUserName"])
	// 4648 (logon attempted using explicit credentials) is deliberately NOT mapped.
	// It records that a process SUPPLIED credentials — it says nothing about whether
	// the logon succeeded. Mapping it to Success=true fabricated logins that never
	// happened: APIs like PrincipalContext.ValidateCredentials emit 4625 AND 4648 for
	// the same failed attempt, so AuthAttackScorer saw "many failures, then a
	// success" and raised a severity-8 "account compromised" alert against accounts
	// that do not exist (validation host, 2026-08-05).
	//
	// AuthEvent has no way to say "attempt, outcome unknown" — Success is a bool.
	// Dropping it is therefore strictly better than lying about the outcome.
	// Reinstating it needs an outcome-neutral representation on the wire AND a
	// matching skip in AuthAttackScorer, not just this case re-added.
	//
	// (2026-08-14: the original wording of this comment also said "auth events
	// carry no EventID field". That is no longer true — AuthEvent.EventID was
	// added for 4765/4766 — but it does not change the verdict here. 4648's
	// problem is the missing outcome, not the missing id, and the skip in
	// AuthAttackScorer that 4765/4766 now has is exactly the second half this
	// comment asked for.)
	default:
		return collector.AuthEvent{}, fmt.Errorf("unhandled event ID %d", raw.System.EventID)
	}

	// Skip system/noise accounts that generate high-frequency, low-value events.
	switch evt.Username {
	case "", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1":
		return collector.AuthEvent{}, fmt.Errorf("system account %q skipped", evt.Username)
	}

	return evt, nil
}

// logonTypeToMethod maps Windows logon type codes to human-readable method names.
func logonTypeToMethod(logonType string) string {
	switch logonType {
	case "2":
		return "interactive"
	case "3":
		return "network"
	case "4":
		return "batch"
	case "5":
		return "service"
	case "7":
		return "unlock"
	case "8":
		return "network_cleartext"
	case "9":
		return "new_credentials"
	case "10":
		return "remote_interactive"
	case "11":
		return "cached_interactive"
	default:
		return "unknown"
	}
}

// authFirstNonEmpty returns the first non-empty, non-dash string value.
func authFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && v != "-" {
			return v
		}
	}
	return ""
}
