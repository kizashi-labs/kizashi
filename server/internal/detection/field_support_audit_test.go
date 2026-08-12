package detection

import (
	"strings"
	"testing"
)

// supportedSigmaFields / ruleSelectedFields were promoted to production
// (field_support.go) as SupportedSigmaFields / RuleSelectedFields so the same
// field-support gate guards both this audit and curate-enabling of SigmaHQ-synced
// rules (roadmap P1). This audit uses the production functions directly.

// TestBuiltinRuleFieldSupportAudit reports built-in rules that select on fields
// the live telemetry cannot populate (inert in production). Informational +
// regression: the count of inert rules must not grow (allowlist below).
func TestBuiltinRuleFieldSupportAudit(t *testing.T) {
	supported := SupportedSigmaFields()

	type finding struct {
		title  string
		unsupp []string
	}
	var findings []finding
	for _, ruleYAML := range builtinSigmaRules {
		title := ""
		for _, ln := range strings.Split(ruleYAML, "\n") {
			if s := strings.TrimSpace(ln); strings.HasPrefix(s, "title:") {
				title = strings.TrimSpace(strings.TrimPrefix(s, "title:"))
				break
			}
		}
		var unsupp []string
		for _, f := range RuleSelectedFields(ruleYAML) {
			if !supported[f] && !supported[strings.ToLower(f)] {
				unsupp = append(unsupp, f)
			}
		}
		if len(unsupp) > 0 {
			findings = append(findings, finding{title, unsupp})
		}
	}

	// knownInert: built-in rules that select on fields our telemetry cannot
	// populate, but whose ATT&CK technique IS covered by another path. They are
	// kept as Sysmon-form rules that would light up if richer telemetry (Sysmon
	// EID 10 / Windows event-log IDs / file contents) is ever added. New entries
	// must NOT appear without justification — that is the regression this guards.
	knownInert := map[string]string{
		"LSASS Memory Dump via Process Access": "Sysmon EID10 (GrantedAccess/TargetImage); covered live by credential_access typedFindings → [CRED] T1003.001",
		"Linux の疑わしい cron ジョブ追加":               "needs file Contents; cron persistence covered by the /etc/cron* path rule (T1053.003)",
	}

	t.Logf("フィールド被覆監査: %d/%d ルールが未サポートのフィールドを選択", len(findings), len(builtinSigmaRules))
	for _, f := range findings {
		note, known := knownInert[f.title]
		status := "INERT?"
		if known {
			status = "known-gap"
		}
		t.Logf("  [%s] %-55s 未サポート: %v", status, f.title, f.unsupp)
		if !known {
			t.Errorf("NEW inert rule %q selects on unsupported fields %v — add a telemetry source/alias, rewrite to supported fields, or justify in knownInert (silent production death, cf. the basename bug)", f.title, f.unsupp)
		}
		_ = note
	}
	// Surface any allowlisted rule that became supported (clean up the allowlist).
	for title := range knownInert {
		found := false
		for _, f := range findings {
			if f.title == title {
				found = true
			}
		}
		if !found {
			t.Logf("  [resolved] %q is now field-supported — remove from knownInert", title)
		}
	}
}
