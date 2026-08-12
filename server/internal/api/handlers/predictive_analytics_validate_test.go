package handlers

import (
	"testing"
)

// ─── computeVulnRisk ─────────────────────────────────────────────────────────

func TestComputeVulnRisk_ZeroAgents_ReturnsZero(t *testing.T) {
	s := riskStats{totalAgents: 0, criticalAlerts: 10}
	if got := computeVulnRisk(s); got != 0 {
		t.Errorf("computeVulnRisk(0 agents) = %v, want 0", got)
	}
}

func TestComputeVulnRisk_NoAlerts_ReturnsZero(t *testing.T) {
	s := riskStats{totalAgents: 10}
	if got := computeVulnRisk(s); got != 0 {
		t.Errorf("computeVulnRisk(no alerts) = %v, want 0", got)
	}
}

func TestComputeVulnRisk_HighAlerts_Positive(t *testing.T) {
	s := riskStats{totalAgents: 5, criticalAlerts: 10, highAlerts: 5}
	got := computeVulnRisk(s)
	if got <= 0 || got > 1 {
		t.Errorf("computeVulnRisk(high alerts) = %v, want in (0,1]", got)
	}
}

func TestComputeVulnRisk_CappedAt1(t *testing.T) {
	s := riskStats{totalAgents: 1, criticalAlerts: 1000}
	got := computeVulnRisk(s)
	if got > 1 {
		t.Errorf("computeVulnRisk: result %v exceeds 1.0", got)
	}
}

// ─── computeIncidentRisk ─────────────────────────────────────────────────────

func TestComputeIncidentRisk_ZeroAlerts_ReturnsZero(t *testing.T) {
	s := riskStats{totalAlerts30d: 0}
	if got := computeIncidentRisk(s); got != 0 {
		t.Errorf("computeIncidentRisk(0 alerts) = %v, want 0", got)
	}
}

func TestComputeIncidentRisk_NotNegative(t *testing.T) {
	s := riskStats{totalAlerts30d: 100, totalAlerts7d: 5}
	got := computeIncidentRisk(s)
	if got < 0 {
		t.Errorf("computeIncidentRisk = %v, must not be negative", got)
	}
}

// ─── computeAgentHealthRisk ───────────────────────────────────────────────────

func TestComputeAgentHealthRisk_ZeroAgents_ReturnsZero(t *testing.T) {
	s := riskStats{totalAgents: 0, offlineAgents: 0}
	if got := computeAgentHealthRisk(s); got != 0 {
		t.Errorf("computeAgentHealthRisk(0 agents) = %v, want 0", got)
	}
}

func TestComputeAgentHealthRisk_AllOffline_Returns1(t *testing.T) {
	s := riskStats{totalAgents: 5, offlineAgents: 5}
	got := computeAgentHealthRisk(s)
	if got != 1.0 {
		t.Errorf("computeAgentHealthRisk(all offline) = %v, want 1.0", got)
	}
}

func TestComputeAgentHealthRisk_NoneOffline_ReturnsZero(t *testing.T) {
	s := riskStats{totalAgents: 10, offlineAgents: 0}
	if got := computeAgentHealthRisk(s); got != 0 {
		t.Errorf("computeAgentHealthRisk(none offline) = %v, want 0", got)
	}
}

// ─── recommendation functions ─────────────────────────────────────────────────

func TestVulnRecommendation_High(t *testing.T) {
	got := vulnRecommendation(0.7)
	if got == "" {
		t.Error("vulnRecommendation(0.7): empty string")
	}
}

func TestVulnRecommendation_Medium(t *testing.T) {
	got := vulnRecommendation(0.5)
	if got == "" {
		t.Error("vulnRecommendation(0.5): empty string")
	}
}

func TestVulnRecommendation_Low(t *testing.T) {
	got := vulnRecommendation(0.1)
	if got == "" {
		t.Error("vulnRecommendation(0.1): empty string")
	}
}

func TestAgentSeverity_High(t *testing.T) {
	if got := agentSeverity(0.3); got != "high" {
		t.Errorf("agentSeverity(0.3) = %q, want 'high'", got)
	}
}

func TestAgentSeverity_Medium(t *testing.T) {
	if got := agentSeverity(0.15); got != "medium" {
		t.Errorf("agentSeverity(0.15) = %q, want 'medium'", got)
	}
}

func TestAgentSeverity_Low(t *testing.T) {
	if got := agentSeverity(0.05); got != "low" {
		t.Errorf("agentSeverity(0.05) = %q, want 'low'", got)
	}
}

// ─── predictItoa ─────────────────────────────────────────────────────────────

func TestPredictItoa_Zero(t *testing.T) {
	if got := predictItoa(0); got != "0" {
		t.Errorf("predictItoa(0) = %q, want '0'", got)
	}
}

func TestPredictItoa_Positive(t *testing.T) {
	if got := predictItoa(123); got != "123" {
		t.Errorf("predictItoa(123) = %q, want '123'", got)
	}
}

func TestPredictItoa_Negative(t *testing.T) {
	if got := predictItoa(-42); got != "-42" {
		t.Errorf("predictItoa(-42) = %q, want '-42'", got)
	}
}
