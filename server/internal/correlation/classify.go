package correlation

import "strings"

// DeriveEventSubtypes translates a post-detection alert into the set of
// correlation event-subtype tokens that the built-in rules (see builtins.go)
// filter on.
//
// Why this exists: the correlation rules were written against Sysmon-style
// sub-types like "auth_failure", "lsass_access", "file_encrypted" and
// "network_connection". But the alert pipeline only knows the *base* event
// category the agent emits — "auth", "process", "file", "network", "dns",
// "registry". With exact-match rule filtering, none of the base categories
// ever equalled a rule sub-type, so every built-in correlation rule was inert
// (no incident could ever be created). This function bridges that gap.
//
// Because only ALERTS reach the correlation engine (not raw telemetry), the
// alert's MITRE technique is the meaningful discriminator: an alert tagged with
// a credential-access technique is a credential-dumping signal regardless of
// which base event carried it. The high-severity, low-threshold rules
// (ransomware outbreak, credential-dumping campaign) are therefore gated on the
// MITRE technique — never on the raw base category — so a benign file or
// process alert can never masquerade as ransomware or LSASS theft.
//
// The base category is always included in the returned set so that rules keyed
// directly on a base type keep working.
func DeriveEventSubtypes(baseType, mitreTech string, severity int, data map[string]interface{}) []string {
	set := map[string]struct{}{}
	add := func(vals ...string) {
		for _, v := range vals {
			if v != "" {
				set[v] = struct{}{}
			}
		}
	}

	base := strings.ToLower(strings.TrimSpace(baseType))
	add(base)

	tech := strings.ToUpper(strings.TrimSpace(mitreTech))
	if i := strings.Index(tech, "."); i >= 0 {
		tech = tech[:i] // collapse sub-technique to its base
	}

	// ── Authentication (Lateral Movement via Brute Force) ────────────────
	// Emit a success/failure token from the event data; when the outcome is
	// unknown, emit both so a brute-force chain (many failures + one success)
	// can still correlate.
	if base == "auth" {
		switch authOutcome(data) {
		case "failure":
			add("auth_failure", "failed_login")
		case "success":
			add("auth_success", "login_success")
		default:
			add("auth_failure", "auth_success")
		}
	}
	if tech == "T1110" { // brute force
		add("auth_failure", "failed_login")
	}

	// ── Credential access (Credential Dumping Campaign) ──────────────────
	// Gated on MITRE credential-access techniques or an explicit LSASS target,
	// never on the raw "process" base — so ordinary process alerts don't count.
	switch tech {
	case "T1003", "T1555", "T1552", "T1558", "T1212", "T1187", "T1621":
		add("credential_dump", "lsass_access", "mimikatz_detected")
	}
	if targetIsLSASS(data) {
		add("credential_dump", "lsass_access")
	}

	// ── Impact / encryption (Ransomware Outbreak) ────────────────────────
	// Gated strictly on ATT&CK impact-encryption/destruction techniques.
	switch tech {
	case "T1486", "T1485", "T1490", "T1491", "T1561":
		add("file_encrypted", "ransomware_detected", "file_rename_bulk", "ransom_note_created")
	}

	// ── Persistence (Persistence Establishment) ──────────────────────────
	if base == "registry" {
		add("registry_modified")
	}
	switch tech {
	case "T1053": // scheduled task/job
		add("scheduled_task_created")
	case "T1543", "T1569": // service creation / execution
		add("service_installed")
	case "T1547", "T1546", "T1037": // autostart / boot-init
		add("startup_item_added")
	case "T1112": // registry run keys and similar
		add("registry_modified")
	}

	// ── Command & Control (C2 Beaconing Pattern) ─────────────────────────
	if base == "network" {
		add("network_connection", "outbound_connection")
	}
	if base == "dns" {
		add("dns_query")
	}
	switch tech {
	case "T1071", "T1095", "T1105", "T1102", "T1568", "T1571", "T1573", "T1090":
		add("network_connection")
	}

	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

// authOutcome reports "success", "failure", or "" (unknown) from an auth
// event's fields. Mirrors the field names the agent emits (see field_support.go).
func authOutcome(data map[string]interface{}) string {
	if data == nil {
		return ""
	}
	if v, ok := data["success"].(bool); ok {
		if v {
			return "success"
		}
		return "failure"
	}
	for _, key := range []string{"action", "result", "status", "outcome"} {
		if s, ok := data[key].(string); ok {
			switch strings.ToLower(s) {
			case "failed", "failure", "fail", "denied":
				return "failure"
			case "success", "succeeded", "accepted":
				return "success"
			}
		}
	}
	if _, ok := data["failure_reason"]; ok {
		return "failure"
	}
	return ""
}

// targetIsLSASS reports whether the event's target image is lsass.exe, the
// canonical credential-dumping target (Sysmon EID10 field names).
func targetIsLSASS(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	for _, key := range []string{"target_image", "TargetImage", "targetImage"} {
		if s, ok := data[key].(string); ok && strings.Contains(strings.ToLower(s), "lsass") {
			return true
		}
	}
	return false
}
