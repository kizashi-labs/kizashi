package detection

import "testing"

// Pure-logic coverage for detection helpers that need no DB/network.

func TestDetection_PureHelpers(t *testing.T) {
	// DNS analyzers over a range of inputs.
	for _, q := range []string{"google.com", "kq3v9z7x1p2w8b4n.evil.com", "aaaaaaaaaaaaaaaaaaaaaaaa.exfil.net", ""} {
		_ = AnalyzeDGA(q)
		_ = AnalyzeDNSQuery(q)
	}

	// Sigma field-support introspection.
	_ = SupportedSigmaFields()
	yaml := "title: t\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: \\mimikatz.exe\n  condition: sel\n"
	_ = RuleSelectedFields(yaml)
	_, _ = RuleFieldSupport(yaml)
	_ = RuleCategory(yaml)
	_ = BehavioralRuleReferencedFields("process_name == 'x'")
	_, _ = BehavioralRuleFieldSupportWith("process_name == 'x'", SupportedSigmaFields())

	// Envelope evaluation over a flat event map.
	_ = EvaluateEnvelope("process", map[string]interface{}{"process_name": "nc.exe", "command_line": "nc -e /bin/sh"})

	// Curate planning.
	_ = CurateBatch([]SyncedRule{{ID: "r1", Category: "process_creation", Content: yaml}}, 10, SupportedSigmaFields())

	// Correlation content builder.
	_, _, _ = BuildCorrelationIncidentContent("APT-Cov", []string{"T1059", "T1055"}, 4)

	// Cloud event parsing (invalid + minimal).
	_, _ = ParseCloudEvent([]byte(`{}`))
	_, _ = ParseCloudEvent([]byte(`not-json`))

	// Statistical anomaly detector.
	d := NewStatAnomalyDetector()
	for i := 0; i < 30; i++ {
		d.UpdateBaseline("user-1", "logins", float64(i%5))
	}
	_ = d.CheckAnomaly("user-1", "logins", 99)
}
