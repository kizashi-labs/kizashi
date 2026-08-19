package collector

import "testing"

// KerberoastableTicket decides what share of Windows Security 4769 leaves the
// endpoint. It is the only place that decision lives, and it is a real
// trade-off: 4769 is logged per service-ticket by the domain controller, so the
// unfiltered stream is thousands per second, nearly all of it a workstation
// fetching a ticket for a file share.
//
// Getting it wrong is quiet in both directions — too tight and Kerberoasting
// goes undetected, too loose and ingestion drowns — so both directions are
// pinned here.

// The headline: the shape Kerberoasting produces is forwarded.
func TestAKerberoastableTicketIsForwarded(t *testing.T) {
	for _, encType := range []string{"0x17", "0x18", "0x1", "0x3", "RC4-HMAC"} {
		if !KerberoastableTicket("alice@CORP.LOCAL", "MSSQLSvc/db01.corp.local:1433", encType) {
			t.Errorf("暗号化方式 %s のサービスチケット要求が転送されません。"+
				"RC4/DES はオフラインで解読可能で、Kerberoasting の唯一の観測点です",
				encType)
		}
	}
}

// AES tickets are the ordinary case and are not forwarded. Without this the
// filter would pass everything and the test above would be meaningless.
func TestAnAESTicketIsNotForwarded(t *testing.T) {
	for _, encType := range []string{"0x11", "0x12"} {
		if KerberoastableTicket("alice@CORP.LOCAL", "MSSQLSvc/db01:1433", encType) {
			t.Errorf("AES (%s) のチケットを転送しています。"+
				"実務上解読できないため、これを送るとドメインコントローラの"+
				"通常トラフィックをそのまま取り込むことになります", encType)
		}
	}
}

// Machine accounts hold a 120-character password that rotates every 30 days.
// Their tickets are not worth cracking and they are most of the traffic.
func TestMachineAccountTicketsAreNotForwarded(t *testing.T) {
	cases := []struct{ user, service string }{
		{"WKSTN01$@CORP.LOCAL", "MSSQLSvc/db01:1433"}, // requested by a machine
		{"alice@CORP.LOCAL", "DC01$"},                 // for a machine
		{"WKSTN01$", "FILESRV$"},
	}
	for _, c := range cases {
		if KerberoastableTicket(c.user, c.service, "0x17") {
			t.Errorf("マシンアカウント (%s -> %s) のチケットを転送しています",
				c.user, c.service)
		}
	}
}

// A ticket for krbtgt itself is deliberately kept: it is what a golden-ticket
// forge looks like, and the server scores it 90.
func TestAKrbtgtTicketIsForwarded(t *testing.T) {
	if !KerberoastableTicket("alice@CORP.LOCAL", "krbtgt/CORP.LOCAL", "0x17") {
		t.Error("krbtgt へのサービスチケット要求を落としています。" +
			"ゴールデンチケット生成の兆候で、除外してはいけません")
	}
}

// Missing fields cannot be judged, so they are not forwarded — an event with no
// SPN carries no Kerberoasting signal at all.
func TestATicketWithNothingToJudgeIsNotForwarded(t *testing.T) {
	if KerberoastableTicket("", "", "0x17") {
		t.Error("ユーザもサービスも空のチケットを転送しています")
	}
	if KerberoastableTicket("alice", "MSSQLSvc/db01", "") {
		t.Error("暗号化方式が不明なチケットを転送しています")
	}
}

// The encryption comparison must not be case- or whitespace-sensitive: Windows
// logs the hex string, but the field has been seen as "0X17" and with padding.
func TestTheEncryptionCheckToleratesFormatting(t *testing.T) {
	for _, encType := range []string{" 0x17 ", "0X17", "rc4-hmac", "RC4-HMAC"} {
		if !KerberoastableTicket("alice", "MSSQLSvc/db01", encType) {
			t.Errorf("暗号化方式 %q を弱い方式として認識しません", encType)
		}
	}
}
