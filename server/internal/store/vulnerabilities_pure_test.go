package store

import (
	"testing"
)

// ─── Vulnerability 構造体フィールドテスト ─────────────────────────────────────

// TestVulnerability_DefaultFields は Vulnerability のゼロ値フィールドを確認する
func TestVulnerability_DefaultFields(t *testing.T) {
	var v Vulnerability
	if v.Severity != "" {
		t.Errorf("Severity のデフォルトは空文字列であるべき: got %q", v.Severity)
	}
	if v.Status != "" {
		t.Errorf("Status のデフォルトは空文字列であるべき: got %q", v.Status)
	}
	if v.CVSSScore != nil {
		t.Errorf("CVSSScore のデフォルトは nil であるべき: got %v", v.CVSSScore)
	}
	if v.AgentID != nil {
		t.Errorf("AgentID のデフォルトは nil であるべき: got %v", v.AgentID)
	}
}

// TestVulnerability_SeverityFieldAssignment は既知の severity 値を設定できることを確認する
func TestVulnerability_SeverityFieldAssignment(t *testing.T) {
	cases := []string{"critical", "high", "medium", "low"}
	for _, sev := range cases {
		v := Vulnerability{Severity: sev}
		if v.Severity != sev {
			t.Errorf("Severity = %q, want %q", v.Severity, sev)
		}
	}
}

// TestVulnerability_StatusFieldAssignment は既知の status 値を設定できることを確認する
func TestVulnerability_StatusFieldAssignment(t *testing.T) {
	cases := []string{"open", "mitigated", "patched", "accepted"}
	for _, st := range cases {
		v := Vulnerability{Status: st}
		if v.Status != st {
			t.Errorf("Status = %q, want %q", v.Status, st)
		}
	}
}

// TestVulnerability_CVSSScorePointer は CVSSScore ポインタを設定・参照できることを確認する
func TestVulnerability_CVSSScorePointer(t *testing.T) {
	score := 9.8
	v := Vulnerability{CVSSScore: &score}
	if v.CVSSScore == nil {
		t.Fatal("CVSSScore に値を設定後は nil でないべき")
	}
	if *v.CVSSScore != score {
		t.Errorf("*CVSSScore = %v, want %v", *v.CVSSScore, score)
	}
}

// TestVulnerability_AgentIDPointer は AgentID ポインタを設定・参照できることを確認する
func TestVulnerability_AgentIDPointer(t *testing.T) {
	id := "agent-uuid-1234"
	v := Vulnerability{AgentID: &id}
	if v.AgentID == nil {
		t.Fatal("AgentID に値を設定後は nil でないべき")
	}
	if *v.AgentID != id {
		t.Errorf("*AgentID = %q, want %q", *v.AgentID, id)
	}
}

// ─── CVSS スコア範囲検証ヘルパーテスト ────────────────────────────────────────

// cvssScoreIsValid は CVSS スコアが 0.0〜10.0 の範囲内かを検証する純粋関数
func cvssScoreIsValid(score float64) bool {
	return score >= 0.0 && score <= 10.0
}

// TestCVSSScoreIsValid_ValidRange は有効なスコア範囲が合格することを確認する
func TestCVSSScoreIsValid_ValidRange(t *testing.T) {
	validScores := []float64{0.0, 1.0, 3.9, 5.0, 7.5, 9.8, 10.0}
	for _, s := range validScores {
		if !cvssScoreIsValid(s) {
			t.Errorf("CVSSスコア %v は有効な範囲内であるべき", s)
		}
	}
}

// TestCVSSScoreIsValid_OutOfRange は範囲外スコアが拒否されることを確認する
func TestCVSSScoreIsValid_OutOfRange(t *testing.T) {
	invalidScores := []float64{-0.1, -1.0, 10.1, 11.0, 100.0}
	for _, s := range invalidScores {
		if cvssScoreIsValid(s) {
			t.Errorf("CVSSスコア %v は範囲外として拒否されるべき", s)
		}
	}
}

// TestCVSSScoreIsValid_Boundaries は境界値が正しく処理されることを確認する
func TestCVSSScoreIsValid_Boundaries(t *testing.T) {
	// 0.0 と 10.0 は有効な境界値
	if !cvssScoreIsValid(0.0) {
		t.Error("CVSS 0.0 は有効な境界値であるべき")
	}
	if !cvssScoreIsValid(10.0) {
		t.Error("CVSS 10.0 は有効な境界値であるべき")
	}
}

// ─── 重大度順序付けテスト ──────────────────────────────────────────────────────

// severitySortOrder は重大度文字列をソート順の数値に変換する純粋関数
// vulnerabilities.go の SQL ORDER BY CASE ロジックを反映する
func severitySortOrder(sev string) int {
	switch sev {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	default: // "low" やその他
		return 4
	}
}

// TestSeveritySortOrder_CriticalIsHighestPriority は critical が最優先であることを確認する
func TestSeveritySortOrder_CriticalIsHighestPriority(t *testing.T) {
	if severitySortOrder("critical") != 1 {
		t.Errorf("critical の優先度 = %d, want 1", severitySortOrder("critical"))
	}
}

// TestSeveritySortOrder_OrderIsConsistent は重大度の順序が一貫していることを確認する
func TestSeveritySortOrder_OrderIsConsistent(t *testing.T) {
	// critical < high < medium < low の順序を確認
	if severitySortOrder("critical") >= severitySortOrder("high") {
		t.Error("critical は high より高優先度（小さい数値）であるべき")
	}
	if severitySortOrder("high") >= severitySortOrder("medium") {
		t.Error("high は medium より高優先度であるべき")
	}
	if severitySortOrder("medium") >= severitySortOrder("low") {
		t.Error("medium は low より高優先度であるべき")
	}
}

// TestSeveritySortOrder_UnknownSeverityGetsLowestPriority は不明な重大度が最低優先度を得ることを確認する
func TestSeveritySortOrder_UnknownSeverityGetsLowestPriority(t *testing.T) {
	unknownOrder := severitySortOrder("unknown")
	lowOrder := severitySortOrder("low")
	if unknownOrder != lowOrder {
		t.Errorf("不明な重大度 (%d) は 'low' と同じ優先度 (%d) であるべき", unknownOrder, lowOrder)
	}
}

// ─── VulnFilter 構造体テスト ──────────────────────────────────────────────────

// TestVulnFilter_DefaultLimitIsZero は VulnFilter のデフォルト Limit がゼロであることを確認する
func TestVulnFilter_DefaultLimitIsZero(t *testing.T) {
	var f VulnFilter
	if f.Limit != 0 {
		t.Errorf("VulnFilter.Limit のデフォルト = %d, want 0", f.Limit)
	}
}

// TestVulnFilter_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestVulnFilter_AllFieldsCanBeSet(t *testing.T) {
	f := VulnFilter{
		AgentID:  "agent-1",
		Severity: "critical",
		Status:   "open",
		Search:   "CVE-2024",
		Limit:    25,
		Offset:   50,
	}
	if f.AgentID != "agent-1" {
		t.Errorf("AgentID = %q, want 'agent-1'", f.AgentID)
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want 'critical'", f.Severity)
	}
	if f.Status != "open" {
		t.Errorf("Status = %q, want 'open'", f.Status)
	}
	if f.Search != "CVE-2024" {
		t.Errorf("Search = %q, want 'CVE-2024'", f.Search)
	}
	if f.Limit != 25 {
		t.Errorf("Limit = %d, want 25", f.Limit)
	}
	if f.Offset != 50 {
		t.Errorf("Offset = %d, want 50", f.Offset)
	}
}

// ─── agentIDArg 純粋関数テスト ────────────────────────────────────────────────

// TestAgentIDArg_NilPointerReturnsNil は nil ポインタが nil を返すことを確認する
func TestAgentIDArg_NilPointerReturnsNil(t *testing.T) {
	result := agentIDArg(nil)
	if result != nil {
		t.Errorf("agentIDArg(nil) = %v, want nil", result)
	}
}

// TestAgentIDArg_EmptyStringPointerReturnsNil は空文字列ポインタが nil を返すことを確認する
func TestAgentIDArg_EmptyStringPointerReturnsNil(t *testing.T) {
	s := ""
	result := agentIDArg(&s)
	if result != nil {
		t.Errorf("agentIDArg(&\"\") = %v, want nil", result)
	}
}

// TestAgentIDArg_NonEmptyStringReturnsValue は非空文字列ポインタが値を返すことを確認する
func TestAgentIDArg_NonEmptyStringReturnsValue(t *testing.T) {
	s := "agent-uuid-abc"
	result := agentIDArg(&s)
	if result == nil {
		t.Fatal("agentIDArg(&s) は nil でないべき")
	}
	if result.(string) != s {
		t.Errorf("agentIDArg(&s) = %v, want %q", result, s)
	}
}

// TestAgentIDArg_UUIDFormatStringReturnsValue は UUID 形式の文字列がそのまま返されることを確認する
func TestAgentIDArg_UUIDFormatStringReturnsValue(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	result := agentIDArg(&uuid)
	if result == nil {
		t.Fatal("UUID 形式の文字列ポインタは nil でないべき")
	}
	if result.(string) != uuid {
		t.Errorf("agentIDArg 結果 = %q, want %q", result.(string), uuid)
	}
}
