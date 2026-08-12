package compliance_test

import (
	"testing"
	"time"

	"github.com/edr-platform/server/internal/compliance"
)

// これらのテストは各フレームワークの control Check 関数の
// pass / fail / unknown 判定を「値」まで検証する。
// 従来の TestCheckResult_Statuses は「有効な status のいずれか」しか見ていなかったため、
// 個々の判定閾値（24h / 48h / アラート件数など）の分岐を確定的に固定する。

// findControl は指定フレームワークから ID 一致の Control を返す（テスト用ヘルパー）。
func findControl(t *testing.T, controls []compliance.Control, id string) compliance.Control {
	t.Helper()
	for _, c := range controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %q が見つかりません", id)
	return compliance.Control{}
}

func assertStatus(t *testing.T, got compliance.CheckResult, want string) {
	t.Helper()
	if got.Status != want {
		t.Errorf("status: got %q, want %q (evidence=%q)", got.Status, want, got.Evidence)
	}
}

var (
	recent = time.Now().Add(-1 * time.Hour)
	stale  = time.Now().Add(-72 * time.Hour)
)

// ─── CIS ────────────────────────────────────────────────────────────────────────

func TestCIS_1_1_AssetInventory(t *testing.T) {
	c := findControl(t, compliance.CISControls(), "CIS-1.1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")                             // LastSeen ゼロ
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: stale}), "fail")                 // 24h 超
	assertStatus(t, c.Check(compliance.AgentComplianceData{Hostname: "h", LastSeen: recent}), "pass") // 直近
}

func TestCIS_4_1_SecureConfig(t *testing.T) {
	c := findControl(t, compliance.CISControls(), "CIS-4.1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown") // version 空
	assertStatus(t, c.Check(compliance.AgentComplianceData{AgentVersion: "1.2.3"}), "pass")
}

func TestCIS_8_2_AuditLog(t *testing.T) {
	c := findControl(t, compliance.CISControls(), "CIS-8.2")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")                               // LastSeen ゼロ
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentEvents: 0}), "fail") // イベント無し
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentEvents: 42}), "pass")
}

func TestCIS_10_1_MalwareDefense(t *testing.T) {
	c := findControl(t, compliance.CISControls(), "CIS-10.1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 3}), "fail") // 閾値3以上
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 2}), "pass")
}

func TestCIS_13_1_NetworkMonitoring(t *testing.T) {
	c := findControl(t, compliance.CISControls(), "CIS-13.1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, NetworkEvents: 0}), "fail")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, NetworkEvents: 5}), "pass")
}

// ─── NIST CSF ─────────────────────────────────────────────────────────────────

func TestNIST_IDAM1_Identify(t *testing.T) {
	c := findControl(t, compliance.NISTControls(), "ID.AM-1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")                                // EnrolledAt ゼロ
	assertStatus(t, c.Check(compliance.AgentComplianceData{EnrolledAt: stale}), "fail")                  // 登録済だが未報告
	assertStatus(t, c.Check(compliance.AgentComplianceData{EnrolledAt: stale, LastSeen: stale}), "fail") // 48h 超
	assertStatus(t, c.Check(compliance.AgentComplianceData{EnrolledAt: stale, LastSeen: recent}), "pass")
}

func TestNIST_PRDS1_AlwaysUnknownWithoutHardening(t *testing.T) {
	c := findControl(t, compliance.NISTControls(), "PR.DS-1")
	// ハードニングテレメトリが無いので常に unknown（誤った pass/fail を出さない設計）
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentEvents: 100}), "unknown")
}

func TestNIST_DECM7_UnauthorizedActivity(t *testing.T) {
	c := findControl(t, compliance.NISTControls(), "DE.CM-7")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentEvents: 0}), "fail") // イベント0
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: stale, RecentEvents: 10}), "fail") // 24h超
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentEvents: 10}), "pass")
}

func TestNIST_RSAN1_AlertBacklog(t *testing.T) {
	c := findControl(t, compliance.NISTControls(), "RS.AN-1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 10}), "fail") // 閾値10
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 9}), "pass")
}

// ─── SOC 2 ────────────────────────────────────────────────────────────────────

func TestSOC2_CC6_1_AccessControl(t *testing.T) {
	c := findControl(t, compliance.SOC2Controls(), "CC6.1")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: stale}), "fail")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent}), "pass")
}

func TestSOC2_CC7_3_IncidentResponse(t *testing.T) {
	c := findControl(t, compliance.SOC2Controls(), "CC7.3")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 20}), "fail") // 閾値20
	assertStatus(t, c.Check(compliance.AgentComplianceData{LastSeen: recent, RecentAlerts: 19}), "pass")
}

func TestSOC2_CC9_2_RiskMitigation(t *testing.T) {
	c := findControl(t, compliance.SOC2Controls(), "CC9.2")
	assertStatus(t, c.Check(compliance.AgentComplianceData{}), "unknown")                                  // version 空
	assertStatus(t, c.Check(compliance.AgentComplianceData{AgentVersion: "1.0", LastSeen: stale}), "fail") // 48h 超
	assertStatus(t, c.Check(compliance.AgentComplianceData{AgentVersion: "1.0", LastSeen: recent}), "pass")
}
