package collector

import "strings"

// Kerberos service-ticket telemetry, from Windows Security 4769 (TGS-REQ).
//
// 4769 is the input to Kerberoasting detection. An attacker enumerates accounts
// that have a Service Principal Name, requests a service ticket for one, and
// asks for RC4 so the ticket comes back encrypted with the service account's
// NTLM hash — which is then cracked offline, away from the domain controller and
// without a single failed logon. The observable is the request itself: an SPN
// plus a weak encryption type.
//
// ldap.DetectKerberoasting has always keyed on exactly that, and has never had
// it: AuthEvent carried no Kerberos fields, so target_spn and
// ticket_encryption_type were NULL on every row and the query could not match.
//
// ── Why this is filtered on the endpoint ──────────────────────────────────
//
// 4769 is logged by the domain controller, once per service-ticket request. On
// a busy DC that is thousands per second, nearly all of it a workstation
// fetching a ticket for a file share. Shipping it whole would swamp ingestion
// for no detection value.
//
// So the agent forwards only what the detection actually needs: a request whose
// ticket is encrypted with a weak cipher, from a real user account. That keeps
// the volume proportional to the signal.
//
// The consequence is stated rather than buried: the server does NOT see every
// service-ticket request. Any future detection that needs the full stream —
// ticket-request rate per user, say, or a golden-ticket lifetime check — needs
// this filter widened, and cannot be written against the DB as if the whole
// stream were there. weakTicketEncryption below is the one place that decision
// lives.

// weakTicketEncryption reports whether a 4769 TicketEncryptionType is one an
// attacker downgrades to in order to crack the ticket offline.
//
//	0x1  DES-CBC-CRC     0x3  DES-CBC-MD5     (long dead, always suspicious)
//	0x17 RC4-HMAC        0x18 RC4-HMAC-EXP    (the Kerberoasting workhorse)
//	0x11 AES128          0x12 AES256          (not crackable in practice)
func weakTicketEncryption(encType string) bool {
	switch strings.ToLower(strings.TrimSpace(encType)) {
	case "0x1", "0x01", "0x3", "0x03", "0x17", "0x18",
		"des-cbc-crc", "des-cbc-md5", "rc4-hmac", "rc4-hmac-exp":
		return true
	}
	return false
}

// isMachineAccount reports whether a Kerberos principal is a computer account.
// Machine accounts end with '$' and hold a 120-character random password that
// rotates every 30 days, so their tickets are not worth cracking — and they are
// the overwhelming majority of 4769 traffic.
func isMachineAccount(name string) bool {
	name = strings.TrimSpace(name)
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	return strings.HasSuffix(name, "$")
}

// Kerberoastable reports whether a 4769 service-ticket request is worth
// forwarding: a weak ticket cipher, requested by a real account, for a real
// service. Everything else is the routine traffic of a working domain.
//
// krbtgt is deliberately NOT excluded. A service ticket for krbtgt itself is
// not routine — it is what a golden-ticket forge looks like — and
// DetectKerberoasting scores it 90.
func KerberoastableTicket(targetUser, serviceName, encType string) bool {
	if !weakTicketEncryption(encType) {
		return false
	}
	if serviceName == "" || isMachineAccount(serviceName) {
		return false
	}
	if targetUser == "" || isMachineAccount(targetUser) {
		return false
	}
	return true
}
