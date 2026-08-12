package compliance

import (
	"testing"
	"time"
)

// healthy returns an AgentComplianceData that passes the typical "all good" path.
func healthy() AgentComplianceData {
	now := time.Now()
	return AgentComplianceData{
		AgentID:       "a1",
		Hostname:      "host-1",
		AgentVersion:  "1.2.3",
		LastSeen:      now.Add(-time.Hour),
		EnrolledAt:    now.Add(-30 * 24 * time.Hour),
		RecentEvents:  100,
		RecentAlerts:  0,
		NetworkEvents: 50,
	}
}

// withLastSeen returns a copy of healthy() with LastSeen overridden.
func withLastSeen(age time.Duration) AgentComplianceData {
	d := healthy()
	d.LastSeen = time.Now().Add(-age)
	return d
}

func checkStatus(t *testing.T, name string, fn func(AgentComplianceData) CheckResult, d AgentComplianceData, want string) {
	t.Helper()
	got := fn(d).Status
	if got != want {
		t.Errorf("%s: got status %q, want %q", name, got, want)
	}
}

// ─── CIS ────────────────────────────────────────────────────────────────────

func TestCIS_CTRL1_1_AssetInventory(t *testing.T) {
	checkStatus(t, "healthy", cisCTRL1_1, healthy(), "pass")
	checkStatus(t, "no last-seen", cisCTRL1_1, AgentComplianceData{}, "unknown")
	checkStatus(t, "stale >24h", cisCTRL1_1, withLastSeen(25*time.Hour), "fail")
}

func TestCIS_CTRL4_1_SecureConfig(t *testing.T) {
	checkStatus(t, "has version", cisCTRL4_1, healthy(), "pass")
	d := healthy()
	d.AgentVersion = ""
	checkStatus(t, "no version", cisCTRL4_1, d, "unknown")
}

func TestCIS_CTRL8_2_AuditLogs(t *testing.T) {
	checkStatus(t, "events flowing", cisCTRL8_2, healthy(), "pass")
	checkStatus(t, "no telemetry", cisCTRL8_2, AgentComplianceData{}, "unknown")
	d := healthy()
	d.RecentEvents = 0
	checkStatus(t, "zero events", cisCTRL8_2, d, "fail")
}

func TestCIS_CTRL10_1_MalwareDefense(t *testing.T) {
	checkStatus(t, "no alerts", cisCTRL10_1, healthy(), "pass")
	checkStatus(t, "no telemetry", cisCTRL10_1, AgentComplianceData{}, "unknown")
	d := healthy()
	d.RecentAlerts = 2
	checkStatus(t, "below threshold", cisCTRL10_1, d, "pass")
	d.RecentAlerts = 3
	checkStatus(t, "at threshold", cisCTRL10_1, d, "fail")
}

func TestCIS_CTRL13_1_NetworkMonitoring(t *testing.T) {
	checkStatus(t, "network flowing", cisCTRL13_1, healthy(), "pass")
	checkStatus(t, "no telemetry", cisCTRL13_1, AgentComplianceData{}, "unknown")
	d := healthy()
	d.NetworkEvents = 0
	checkStatus(t, "zero network", cisCTRL13_1, d, "fail")
}

// ─── NIST CSF ───────────────────────────────────────────────────────────────

func TestNIST_IDam1_AssetManagement(t *testing.T) {
	checkStatus(t, "healthy", nistIDam1, healthy(), "pass")
	checkStatus(t, "never enrolled", nistIDam1, AgentComplianceData{}, "unknown")
	d := healthy()
	d.LastSeen = time.Time{} // enrolled but never reported
	checkStatus(t, "enrolled never reported", nistIDam1, d, "fail")
	checkStatus(t, "stale >48h", nistIDam1, withLastSeen(49*time.Hour), "fail")
}

func TestNIST_PRds1_DataAtRest_AlwaysUnknown(t *testing.T) {
	// Without hardening telemetry this control conservatively returns unknown.
	checkStatus(t, "healthy still unknown", nistPRds1, healthy(), "unknown")
	checkStatus(t, "no telemetry", nistPRds1, AgentComplianceData{}, "unknown")
}

func TestNIST_DEcm1_NetworkMonitored(t *testing.T) {
	checkStatus(t, "network flowing", nistDEcm1, healthy(), "pass")
	checkStatus(t, "no telemetry", nistDEcm1, AgentComplianceData{}, "unknown")
	d := healthy()
	d.NetworkEvents = 0
	checkStatus(t, "zero network", nistDEcm1, d, "fail")
}

func TestNIST_DEcm7_UnauthorizedActivity(t *testing.T) {
	checkStatus(t, "active+events", nistDEcm7, healthy(), "pass")
	checkStatus(t, "no telemetry", nistDEcm7, AgentComplianceData{}, "unknown")
	stale := withLastSeen(25 * time.Hour)
	checkStatus(t, "stale", nistDEcm7, stale, "fail")
	d := healthy()
	d.RecentEvents = 0
	checkStatus(t, "no events", nistDEcm7, d, "fail")
}

func TestNIST_RSan1_AlertInvestigation(t *testing.T) {
	checkStatus(t, "manageable", nistRSan1, healthy(), "pass")
	checkStatus(t, "no telemetry", nistRSan1, AgentComplianceData{}, "unknown")
	d := healthy()
	d.RecentAlerts = 9
	checkStatus(t, "below 10", nistRSan1, d, "pass")
	d.RecentAlerts = 10
	checkStatus(t, "at 10", nistRSan1, d, "fail")
}

// ─── SOC 2 ──────────────────────────────────────────────────────────────────

func TestSOC2_CC6_1_LogicalAccess(t *testing.T) {
	checkStatus(t, "active", soc2CC6_1, healthy(), "pass")
	checkStatus(t, "no telemetry", soc2CC6_1, AgentComplianceData{}, "unknown")
	checkStatus(t, "stale >24h", soc2CC6_1, withLastSeen(25*time.Hour), "fail")
}

func TestSOC2_CC7_2_SystemMonitoring(t *testing.T) {
	checkStatus(t, "events", soc2CC7_2, healthy(), "pass")
	checkStatus(t, "no telemetry", soc2CC7_2, AgentComplianceData{}, "unknown")
	d := healthy()
	d.RecentEvents = 0
	checkStatus(t, "no events", soc2CC7_2, d, "fail")
}

func TestSOC2_CC7_3_IncidentResponse(t *testing.T) {
	checkStatus(t, "manageable", soc2CC7_3, healthy(), "pass")
	checkStatus(t, "no telemetry", soc2CC7_3, AgentComplianceData{}, "unknown")
	d := healthy()
	d.RecentAlerts = 19
	checkStatus(t, "below 20", soc2CC7_3, d, "pass")
	d.RecentAlerts = 20
	checkStatus(t, "at 20", soc2CC7_3, d, "fail")
}

func TestSOC2_CC9_2_RiskMitigation(t *testing.T) {
	checkStatus(t, "managed", soc2CC9_2, healthy(), "pass")
	d := healthy()
	d.AgentVersion = ""
	checkStatus(t, "no version", soc2CC9_2, d, "unknown")
	checkStatus(t, "stale >48h", soc2CC9_2, withLastSeen(49*time.Hour), "fail")
}

// ─── Framework wiring smoke test ────────────────────────────────────────────

// TestAllControls_WiredAndRunnable runs every control's Check against a healthy
// fixture and asserts the Check func is wired and returns a valid status.
func TestAllControls_WiredAndRunnable(t *testing.T) {
	valid := map[string]bool{"pass": true, "fail": true, "unknown": true}
	groups := [][]Control{CISControls(), NISTControls(), SOC2Controls()}
	d := healthy()
	for _, controls := range groups {
		for _, c := range controls {
			if c.ID == "" || c.Title == "" {
				t.Errorf("control missing ID/Title: %+v", c)
			}
			if c.Check == nil {
				t.Errorf("control %s has nil Check", c.ID)
				continue
			}
			if st := c.Check(d).Status; !valid[st] {
				t.Errorf("control %s returned invalid status %q", c.ID, st)
			}
		}
	}
}
