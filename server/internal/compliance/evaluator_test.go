package compliance_test

import (
	"testing"
	"time"

	"github.com/edr-platform/server/internal/compliance"
)

// ─── Framework constants ───────────────────────────────────────────────────────

func TestFrameworkConstants(t *testing.T) {
	tests := []struct {
		name  string
		value compliance.Framework
		want  string
	}{
		{"CIS", compliance.FrameworkCIS, "cis"},
		{"NIST", compliance.FrameworkNIST, "nist"},
		{"SOC2", compliance.FrameworkSOC2, "soc2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.value) != tc.want {
				t.Errorf("Framework%s = %q; want %q", tc.name, tc.value, tc.want)
			}
		})
	}
}

// ─── Control list counts ───────────────────────────────────────────────────────

func TestCISControls_Count(t *testing.T) {
	controls := compliance.CISControls()
	if len(controls) < 5 {
		t.Errorf("CISControls() returned %d controls; want at least 5", len(controls))
	}
}

func TestNISTControls_Count(t *testing.T) {
	controls := compliance.NISTControls()
	if len(controls) < 5 {
		t.Errorf("NISTControls() returned %d controls; want at least 5", len(controls))
	}
}

func TestSOC2Controls_Count(t *testing.T) {
	controls := compliance.SOC2Controls()
	if len(controls) < 4 {
		t.Errorf("SOC2Controls() returned %d controls; want at least 4", len(controls))
	}
}

// ─── CheckResult status constants ─────────────────────────────────────────────

// TestCheckResult_Statuses exercises each check function in the CIS control set
// to confirm that every returned Status is one of the three documented values:
// "pass", "fail", or "unknown".
func TestCheckResult_Statuses(t *testing.T) {
	validStatuses := map[string]bool{
		"pass":    true,
		"fail":    true,
		"unknown": true,
	}

	// Build a matrix of agent data variants to exercise all branches.
	variants := []compliance.AgentComplianceData{
		// Agent that has never reported.
		{
			AgentID:  "agent-zero",
			Hostname: "ghost",
			// zero-value LastSeen / EnrolledAt
		},
		// Agent that has been active recently.
		{
			AgentID:       "agent-active",
			Hostname:      "active-host",
			OSType:        "linux",
			AgentVersion:  "1.2.3",
			Status:        "online",
			LastSeen:      time.Now().Add(-1 * time.Hour),
			EnrolledAt:    time.Now().Add(-30 * 24 * time.Hour),
			RecentEvents:  500,
			RecentAlerts:  1,
			NetworkEvents: 200,
		},
		// Agent that is stale (> 24h since last seen).
		{
			AgentID:       "agent-stale",
			Hostname:      "stale-host",
			AgentVersion:  "1.0.0",
			Status:        "offline",
			LastSeen:      time.Now().Add(-48 * time.Hour),
			EnrolledAt:    time.Now().Add(-60 * 24 * time.Hour),
			RecentEvents:  0,
			RecentAlerts:  0,
			NetworkEvents: 0,
		},
		// Agent with high alert count (should trigger "fail" for malware/incident controls).
		{
			AgentID:       "agent-alerted",
			Hostname:      "alerted-host",
			AgentVersion:  "1.2.3",
			Status:        "online",
			LastSeen:      time.Now().Add(-10 * time.Minute),
			EnrolledAt:    time.Now().Add(-7 * 24 * time.Hour),
			RecentEvents:  100,
			RecentAlerts:  25,
			NetworkEvents: 0,
		},
	}

	for _, controls := range [][]compliance.Control{
		compliance.CISControls(),
		compliance.NISTControls(),
		compliance.SOC2Controls(),
	} {
		for _, ctrl := range controls {
			for _, agentData := range variants {
				result := ctrl.Check(agentData)
				if !validStatuses[result.Status] {
					t.Errorf("control %s Check() returned invalid status %q for agent %q; must be 'pass', 'fail', or 'unknown'",
						ctrl.ID, result.Status, agentData.Hostname)
				}
			}
		}
	}
}

// ─── Control required fields ───────────────────────────────────────────────────

func TestControl_HasRequiredFields(t *testing.T) {
	controls := compliance.CISControls()

	for _, ctrl := range controls {
		t.Run(ctrl.ID, func(t *testing.T) {
			if ctrl.ID == "" {
				t.Error("Control.ID must not be empty")
			}
			if ctrl.Title == "" {
				t.Errorf("Control %q: Title must not be empty", ctrl.ID)
			}
			if ctrl.Check == nil {
				t.Errorf("Control %q: Check func must not be nil", ctrl.ID)
			}
		})
	}
}
