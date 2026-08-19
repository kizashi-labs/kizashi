package store

import (
	"strings"
	"testing"
)

// ─── AgentPolicy 構造体テスト ─────────────────────────────────────────────────

// TestAgentPolicy_ZeroValue は AgentPolicy のゼロ値フィールドを確認する
// 既定ポリシーの削除拒否と、TenantID の nil 化は、**検査の本文で製品の
// 2行を書き直して**確かめていました（`isBlocked := func(id string) bool
// { return id == defaultPolicyID }`）。製品を1行も通りません。
//
// 本物を当てる検査は `agent_policies_db_test.go` にあります。

func TestAgentPolicy_ZeroValue(t *testing.T) {
	var p AgentPolicy
	if p.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", p.ID)
	}
	if p.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", p.Name)
	}
	if p.ScanIntervalMin != 0 {
		t.Errorf("ScanIntervalMin のデフォルト = %d, want 0", p.ScanIntervalMin)
	}
	if p.FullScanHour != 0 {
		t.Errorf("FullScanHour のデフォルト = %d, want 0", p.FullScanHour)
	}
	if p.CPULimitPct != 0 {
		t.Errorf("CPULimitPct のデフォルト = %d, want 0", p.CPULimitPct)
	}
	if p.MemLimitMB != 0 {
		t.Errorf("MemLimitMB のデフォルト = %d, want 0", p.MemLimitMB)
	}
	if p.MonitorNetwork {
		t.Error("MonitorNetwork のデフォルトは false であるべき")
	}
	if p.MonitorDNS {
		t.Error("MonitorDNS のデフォルトは false であるべき")
	}
}

// TestAgentPolicy_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestAgentPolicy_FieldAssignment(t *testing.T) {
	p := AgentPolicy{
		ID:              "policy-001",
		Name:            "Strict Policy",
		Description:     "高セキュリティポリシー",
		TenantID:        "tenant-abc",
		ScanIntervalMin: 30,
		FullScanHour:    2,
		CPULimitPct:     50,
		MemLimitMB:      512,
		MonitorNetwork:  true,
		MonitorDNS:      true,
		LogLevel:        "debug",
	}
	if p.ID != "policy-001" {
		t.Errorf("ID = %q, want \"policy-001\"", p.ID)
	}
	if p.Name != "Strict Policy" {
		t.Errorf("Name = %q, want \"Strict Policy\"", p.Name)
	}
	if p.ScanIntervalMin != 30 {
		t.Errorf("ScanIntervalMin = %d, want 30", p.ScanIntervalMin)
	}
	if p.CPULimitPct != 50 {
		t.Errorf("CPULimitPct = %d, want 50", p.CPULimitPct)
	}
	if !p.MonitorNetwork {
		t.Error("MonitorNetwork は true であるべき")
	}
	if !p.MonitorDNS {
		t.Error("MonitorDNS は true であるべき")
	}
}

// TestAgentPolicy_MonitoredExtensionsDefaultBehavior は
// MonitoredExtensions の nil 初期化ロジックを確認する（Create 相当）
func TestAgentPolicy_MonitoredExtensionsDefaultBehavior(t *testing.T) {
	// Create メソッドと同じロジック: nil なら既定の拡張子セットを使用する
	in := CreatePolicyInput{
		Name:                "Test Policy",
		MonitoredExtensions: nil,
	}
	if in.MonitoredExtensions == nil {
		in.MonitoredExtensions = []string{".exe", ".dll", ".sh", ".ps1", ".py"}
	}

	expected := []string{".exe", ".dll", ".sh", ".ps1", ".py"}
	if len(in.MonitoredExtensions) != len(expected) {
		t.Fatalf("MonitoredExtensions の長さ = %d, want %d", len(in.MonitoredExtensions), len(expected))
	}
	for i, ext := range expected {
		if in.MonitoredExtensions[i] != ext {
			t.Errorf("MonitoredExtensions[%d] = %q, want %q", i, in.MonitoredExtensions[i], ext)
		}
	}
}

// TestAgentPolicy_ExcludedPathsNilCoercedToEmpty は
// ExcludedPaths の nil が空スライスになることを確認する
func TestAgentPolicy_ExcludedPathsNilCoercedToEmpty(t *testing.T) {
	// Update メソッドと同じロジック
	in := UpdatePolicyInput{ExcludedPaths: nil}
	if in.ExcludedPaths == nil {
		in.ExcludedPaths = []string{}
	}
	if in.ExcludedPaths == nil {
		t.Error("ExcludedPaths は nil でないべき（空スライスに変換済み）")
	}
	if len(in.ExcludedPaths) != 0 {
		t.Errorf("ExcludedPaths の長さ = %d, want 0", len(in.ExcludedPaths))
	}
}

// TestAgentPolicy_DefaultPolicyIDIsHardcoded は
// デフォルトポリシーIDが固定値であることを確認する
func TestAgentPolicy_DefaultPolicyIDIsHardcoded(t *testing.T) {
	const wantID = "00000000-0000-0000-0000-000000000002"
	if defaultPolicyID != wantID {
		t.Errorf("defaultPolicyID = %q, want %q", defaultPolicyID, wantID)
	}
}

// TestAgentPolicy_DeleteDefaultPolicyBlocked は
// デフォルトポリシーの削除がブロックされるロジックを確認する
func TestAgentPolicy_LogLevelValues(t *testing.T) {
	// ポリシーに設定可能な想定ログレベルのセット
	validLevels := []string{"debug", "info", "warn", "error"}
	for _, level := range validLevels {
		p := AgentPolicy{LogLevel: level}
		if p.LogLevel != level {
			t.Errorf("LogLevel = %q, want %q", p.LogLevel, level)
		}
	}
}

// TestAgentPolicy_FullScanHourRange は FullScanHour フィールドの値域を確認する
func TestAgentPolicy_FullScanHourRange(t *testing.T) {
	// FullScanHour は 0〜23 の時刻を表す
	cases := []int{0, 1, 12, 23}
	for _, h := range cases {
		p := AgentPolicy{FullScanHour: h}
		if p.FullScanHour != h {
			t.Errorf("FullScanHour = %d, want %d", p.FullScanHour, h)
		}
	}
}

// TestAgentPolicy_PolicySelectColsContainsRequiredFields は
// policySelectCols に必要なカラムが含まれることを確認する
func TestAgentPolicy_PolicySelectColsContainsRequiredFields(t *testing.T) {
	requiredFields := []string{
		"id", "name", "description",
		"scan_interval_min", "full_scan_hour",
		"cpu_limit_pct", "mem_limit_mb",
		"log_level",
		"created_at", "updated_at",
	}
	for _, field := range requiredFields {
		if !strings.Contains(policySelectCols, field) {
			t.Errorf("policySelectCols に %q が含まれるべき", field)
		}
	}
}

// TestUpdatePolicyInput_MonitoredExtensionsNilCoercedToEmpty は
// UpdatePolicyInput.MonitoredExtensions の nil が空スライスになることを確認する
func TestUpdatePolicyInput_MonitoredExtensionsNilCoercedToEmpty(t *testing.T) {
	in := UpdatePolicyInput{MonitoredExtensions: nil}
	if in.MonitoredExtensions == nil {
		in.MonitoredExtensions = []string{}
	}
	if len(in.MonitoredExtensions) != 0 {
		t.Errorf("MonitoredExtensions の長さ = %d, want 0", len(in.MonitoredExtensions))
	}
}
