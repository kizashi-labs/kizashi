package handlers

import "testing"

// ─── titleForType ────────────────────────────────────────────────────────────

func TestTitleForType_ExecutiveSummary(t *testing.T) {
	if got := titleForType("executive_summary"); got != "Executive Security Summary" {
		t.Errorf("titleForType(executive_summary) = %q", got)
	}
}

func TestTitleForType_ComplianceReport(t *testing.T) {
	if got := titleForType("compliance_report"); got != "Compliance Status Report" {
		t.Errorf("titleForType(compliance_report) = %q", got)
	}
}

func TestTitleForType_IncidentReport(t *testing.T) {
	if got := titleForType("incident_report"); got != "Incident Report" {
		t.Errorf("titleForType(incident_report) = %q", got)
	}
}

func TestTitleForType_ThreatSummary(t *testing.T) {
	if got := titleForType("threat_summary"); got != "Threat Intelligence Summary" {
		t.Errorf("titleForType(threat_summary) = %q", got)
	}
}

func TestTitleForType_Unknown_DefaultsToSecurityReport(t *testing.T) {
	if got := titleForType("unknown_type"); got != "Security Report" {
		t.Errorf("titleForType(unknown) = %q, want 'Security Report'", got)
	}
}

func TestTitleForType_Empty_DefaultsToSecurityReport(t *testing.T) {
	if got := titleForType(""); got != "Security Report" {
		t.Errorf("titleForType('') = %q, want 'Security Report'", got)
	}
}
