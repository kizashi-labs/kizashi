package handlers

import "testing"

// ─── parseBody ───────────────────────────────────────────────────────────────

func TestParseBody_SyslogPrefix_DetectsSyslog(t *testing.T) {
	got := parseBody("<134>Jan 01 00:00:00 hostname message")
	if got.format != "syslog" {
		t.Errorf("parseBody(syslog): format = %q, want 'syslog'", got.format)
	}
}

func TestParseBody_CEFPrefix_DetectsCEF(t *testing.T) {
	got := parseBody("CEF:0|Vendor|Product|1.0|100|Test|5|")
	if got.format != "cef" {
		t.Errorf("parseBody(CEF): format = %q, want 'cef'", got.format)
	}
}

func TestParseBody_JSONPrefix_DetectsJSON(t *testing.T) {
	got := parseBody(`{"event": "login", "user": "alice"}`)
	if got.format != "json" {
		t.Errorf("parseBody(JSON): format = %q, want 'json'", got.format)
	}
}

// ─── parseSyslog ─────────────────────────────────────────────────────────────

func TestParseSyslog_ExtractsPriority(t *testing.T) {
	got := parseSyslog("<134>Jan 01 00:00:00 host msg")
	if _, ok := got.parsedData["priority"]; !ok {
		t.Error("parseSyslog: missing 'priority' key")
	}
}

func TestParseSyslog_ExtractsFacilityAndSeverity(t *testing.T) {
	// priority 134 = facility 16, severity 6
	got := parseSyslog("<134>Jan 01 00:00:00 host msg")
	if fac, ok := got.parsedData["facility"]; !ok || fac != 16 {
		t.Errorf("parseSyslog: facility = %v, want 16", fac)
	}
	if sev, ok := got.parsedData["severity"]; !ok || sev != 6 {
		t.Errorf("parseSyslog: severity = %v, want 6", sev)
	}
}

func TestParseSyslog_MissingClosingBracket_ReturnsError(t *testing.T) {
	got := parseSyslog("<134 no closing bracket")
	if got.errMsg == "" {
		t.Error("parseSyslog(invalid): expected error message")
	}
}

func TestParseSyslog_ExtractsHostname(t *testing.T) {
	// Use single-token timestamp so parser gets: timestamp=2024-01-01T00:00:00Z, hostname=myhost, message=the message
	got := parseSyslog("<13>2024-01-01T00:00:00Z myhost the message")
	if h, ok := got.parsedData["hostname"]; !ok || h != "myhost" {
		t.Errorf("parseSyslog: hostname = %v, want 'myhost'", h)
	}
}

// ─── parseCEF ────────────────────────────────────────────────────────────────

func TestParseCEF_ExtractsVendor(t *testing.T) {
	got := parseCEF("CEF:0|AcmeCorp|Firewall|1.0|100|Blocked|7|")
	if v, ok := got.parsedData["device_vendor"]; !ok || v != "AcmeCorp" {
		t.Errorf("parseCEF: device_vendor = %v, want 'AcmeCorp'", v)
	}
}

func TestParseCEF_ExtractsSeverity(t *testing.T) {
	got := parseCEF("CEF:0|Vendor|Product|1.0|100|Name|8|")
	if s, ok := got.parsedData["severity"]; !ok || s != "8" {
		t.Errorf("parseCEF: severity = %v, want '8'", s)
	}
}

func TestParseCEF_TooFewFields_ReturnsError(t *testing.T) {
	got := parseCEF("CEF:0|only|three|fields")
	if got.errMsg == "" {
		t.Error("parseCEF(insufficient fields): expected error message")
	}
}

func TestParseCEF_ExtractsExtensionFields(t *testing.T) {
	got := parseCEF("CEF:0|V|P|1|1|N|5|src=10.0.0.1 dst=10.0.0.2")
	ext, ok := got.parsedData["extension"]
	if !ok {
		t.Fatal("parseCEF: missing 'extension' key")
	}
	extMap, ok := ext.(map[string]string)
	if !ok {
		t.Fatal("parseCEF: extension is not map[string]string")
	}
	if extMap["src"] != "10.0.0.1" {
		t.Errorf("parseCEF: extension.src = %q, want '10.0.0.1'", extMap["src"])
	}
}

// ─── parseJSON ───────────────────────────────────────────────────────────────

func TestParseJSON_ValidJSON_ExtractsFields(t *testing.T) {
	got := parseJSON(`{"user":"alice","action":"login"}`)
	if got.errMsg != "" {
		t.Errorf("parseJSON: unexpected error %q", got.errMsg)
	}
	if got.parsedData["user"] != "alice" {
		t.Errorf("parseJSON: user = %v, want 'alice'", got.parsedData["user"])
	}
}

func TestParseJSON_InvalidJSON_ReturnsError(t *testing.T) {
	got := parseJSON("not json")
	if got.errMsg == "" {
		t.Error("parseJSON(invalid): expected error message")
	}
}
