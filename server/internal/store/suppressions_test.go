package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── SuppressionConditions 構造体テスト ──────────────────────────────────────

// TestSuppressionConditions_ZeroValue はゼロ値が全フィールド空であることを確認する
func TestSuppressionConditions_ZeroValue(t *testing.T) {
	var c SuppressionConditions
	if c.RuleName != "" {
		t.Errorf("RuleName のデフォルト = %q, want \"\"", c.RuleName)
	}
	if c.Hostname != "" {
		t.Errorf("Hostname のデフォルト = %q, want \"\"", c.Hostname)
	}
	if c.SeverityMax != 0 {
		t.Errorf("SeverityMax のデフォルト = %d, want 0", c.SeverityMax)
	}
	if c.MITRETechnique != "" {
		t.Errorf("MITRETechnique のデフォルト = %q, want \"\"", c.MITRETechnique)
	}
	if c.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", c.AgentID)
	}
}

// TestSuppressionConditions_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestSuppressionConditions_FieldAssignment(t *testing.T) {
	c := SuppressionConditions{
		RuleName:       "Test Rule",
		Hostname:       "agent-host-01",
		SeverityMax:    5,
		MITRETechnique: "T1059.001",
		AgentID:        "agent-uuid-abc",
	}
	if c.RuleName != "Test Rule" {
		t.Errorf("RuleName = %q, want \"Test Rule\"", c.RuleName)
	}
	if c.Hostname != "agent-host-01" {
		t.Errorf("Hostname = %q, want \"agent-host-01\"", c.Hostname)
	}
	if c.SeverityMax != 5 {
		t.Errorf("SeverityMax = %d, want 5", c.SeverityMax)
	}
	if c.MITRETechnique != "T1059.001" {
		t.Errorf("MITRETechnique = %q, want \"T1059.001\"", c.MITRETechnique)
	}
	if c.AgentID != "agent-uuid-abc" {
		t.Errorf("AgentID = %q, want \"agent-uuid-abc\"", c.AgentID)
	}
}

// TestSuppressionConditions_JSONMarshal は SuppressionConditions が正しくJSONシリアライズされることを確認する
func TestSuppressionConditions_JSONMarshal(t *testing.T) {
	c := SuppressionConditions{
		RuleName:    "Malware Alert",
		SeverityMax: 8,
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("JSONシリアライズに失敗: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, "Malware Alert") {
		t.Errorf("シリアライズ結果にRuleNameが含まれるべき: %s", out)
	}
	if !strings.Contains(out, "8") {
		t.Errorf("シリアライズ結果にSeverityMaxが含まれるべき: %s", out)
	}
}

// TestSuppressionConditions_JSONUnmarshal は SuppressionConditions が正しくJSONデシリアライズされることを確認する
func TestSuppressionConditions_JSONUnmarshal(t *testing.T) {
	raw := `{"rule_name":"Ransomware","hostname":"win-host","severity_max":9,"mitre_technique":"T1486","agent_id":"uuid-123"}`
	var c SuppressionConditions
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("JSONデシリアライズに失敗: %v", err)
	}
	if c.RuleName != "Ransomware" {
		t.Errorf("RuleName = %q, want \"Ransomware\"", c.RuleName)
	}
	if c.Hostname != "win-host" {
		t.Errorf("Hostname = %q, want \"win-host\"", c.Hostname)
	}
	if c.SeverityMax != 9 {
		t.Errorf("SeverityMax = %d, want 9", c.SeverityMax)
	}
	if c.MITRETechnique != "T1486" {
		t.Errorf("MITRETechnique = %q, want \"T1486\"", c.MITRETechnique)
	}
	if c.AgentID != "uuid-123" {
		t.Errorf("AgentID = %q, want \"uuid-123\"", c.AgentID)
	}
}

// TestSuppressionConditions_OmitEmptyInJSON は空フィールドがJSONに出力されないことを確認する
func TestSuppressionConditions_OmitEmptyInJSON(t *testing.T) {
	// 全フィールドがゼロ値の場合
	c := SuppressionConditions{}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("JSONシリアライズに失敗: %v", err)
	}
	out := string(b)
	// omitempty タグにより空フィールドはJSON出力に現れないはず
	for _, field := range []string{"rule_name", "hostname", "mitre_technique", "agent_id"} {
		if strings.Contains(out, field) {
			t.Errorf("空フィールド %q はJSON出力に現れるべきでない: %s", field, out)
		}
	}
}

// TestSuppressionConditions_RoundTrip はシリアライズ→デシリアライズで値が保持されることを確認する
func TestSuppressionConditions_RoundTrip(t *testing.T) {
	original := SuppressionConditions{
		RuleName:       "Lateral Movement",
		Hostname:       "dc-server-01",
		SeverityMax:    7,
		MITRETechnique: "T1021",
		AgentID:        "550e8400-e29b-41d4-a716-446655440000",
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("シリアライズ失敗: %v", err)
	}
	var restored SuppressionConditions
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatalf("デシリアライズ失敗: %v", err)
	}
	if restored != original {
		t.Errorf("ラウンドトリップ後の値が一致しない:\n got  %+v\n want %+v", restored, original)
	}
}

// ─── SuppressionRule 構造体テスト ─────────────────────────────────────────────

// TestSuppressionRule_DefaultValues は SuppressionRule のゼロ値を確認する
func TestSuppressionRule_DefaultValues(t *testing.T) {
	var r SuppressionRule
	if r.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if r.HitCount != 0 {
		t.Errorf("HitCount のデフォルト = %d, want 0", r.HitCount)
	}
	if r.DurationH != 0 {
		t.Errorf("DurationH のデフォルト = %d, want 0", r.DurationH)
	}
	if r.ExpiresAt != nil {
		t.Errorf("ExpiresAt のデフォルトは nil であるべき")
	}
	if r.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき")
	}
}

// TestSuppressionRule_FieldAssignment はフィールド代入が正しく動作することを確認する
func TestSuppressionRule_FieldAssignment(t *testing.T) {
	createdBy := "user-uuid-123"
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	r := SuppressionRule{
		ID:          "rule-id-001",
		Name:        "Suppress Noise",
		Description: "低深刻度アラートを一時抑制する",
		Conditions: SuppressionConditions{
			Hostname:    "test-host",
			SeverityMax: 3,
		},
		DurationH:     24,
		IsActive:      true,
		HitCount:      42,
		CreatedBy:     &createdBy,
		CreatedByName: "Alice Admin",
		ExpiresAt:     &expires,
	}
	if r.ID != "rule-id-001" {
		t.Errorf("ID = %q, want \"rule-id-001\"", r.ID)
	}
	if r.Name != "Suppress Noise" {
		t.Errorf("Name = %q, want \"Suppress Noise\"", r.Name)
	}
	if r.DurationH != 24 {
		t.Errorf("DurationH = %d, want 24", r.DurationH)
	}
	if !r.IsActive {
		t.Error("IsActive = false, want true")
	}
	if r.HitCount != 42 {
		t.Errorf("HitCount = %d, want 42", r.HitCount)
	}
	if r.CreatedBy == nil || *r.CreatedBy != createdBy {
		t.Errorf("CreatedBy = %v, want %q", r.CreatedBy, createdBy)
	}
	if r.ExpiresAt == nil || !r.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", r.ExpiresAt, expires)
	}
	if r.Conditions.Hostname != "test-host" {
		t.Errorf("Conditions.Hostname = %q, want \"test-host\"", r.Conditions.Hostname)
	}
}

// TestSuppressionRule_IsExpired はルールの有効期限判定ロジックを確認する
func TestSuppressionRule_IsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	// 期限なしルール
	rNoExpiry := SuppressionRule{IsActive: true}
	if rNoExpiry.ExpiresAt != nil {
		t.Error("期限なしルールのExpiresAtはnilであるべき")
	}

	// 期限切れルール — ExpiresAt は過去
	rExpired := SuppressionRule{IsActive: true, ExpiresAt: &past}
	if rExpired.ExpiresAt == nil || !rExpired.ExpiresAt.Before(time.Now()) {
		t.Error("過去のExpiresAtは現在時刻より前であるべき")
	}

	// 有効なルール — ExpiresAt は未来
	rValid := SuppressionRule{IsActive: true, ExpiresAt: &future}
	if rValid.ExpiresAt == nil || !rValid.ExpiresAt.After(time.Now()) {
		t.Error("未来のExpiresAtは現在時刻より後であるべき")
	}
}

// TestSuppressionRule_JSONTags はJSON タグが正しいフィールド名を生成することを確認する
func TestSuppressionRule_JSONTags(t *testing.T) {
	r := SuppressionRule{
		ID:       "test-id",
		Name:     "Test Rule",
		IsActive: true,
		HitCount: 5,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("JSONシリアライズ失敗: %v", err)
	}
	out := string(b)
	for _, expected := range []string{`"id"`, `"name"`, `"is_active"`, `"hit_count"`} {
		if !strings.Contains(out, expected) {
			t.Errorf("JSON出力に %s が含まれるべき: %s", expected, out)
		}
	}
}

// TestSuppressionConditions_SeverityMaxBoundary はSeverityMaxの境界値を確認する
func TestSuppressionConditions_SeverityMaxBoundary(t *testing.T) {
	// SeverityMax=0 はゼロ値（フィルタなし）として扱われる想定
	c0 := SuppressionConditions{SeverityMax: 0}
	if c0.SeverityMax != 0 {
		t.Errorf("SeverityMax=0 が保持されない: got %d", c0.SeverityMax)
	}

	// SeverityMax=10 は最大深刻度
	c10 := SuppressionConditions{SeverityMax: 10}
	if c10.SeverityMax != 10 {
		t.Errorf("SeverityMax=10 が保持されない: got %d", c10.SeverityMax)
	}
}

// ─── SuppressionRuleEntry 構造体テスト（suppression_rule_store.go）────────────

// TestSuppressionRuleEntry_DefaultValues は SuppressionRuleEntry のゼロ値を確認する
func TestSuppressionRuleEntry_DefaultValues(t *testing.T) {
	var e SuppressionRuleEntry
	if e.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if e.SeverityMax != 0 {
		t.Errorf("SeverityMax のデフォルト = %d, want 0", e.SeverityMax)
	}
	if e.SuppressedCount != 0 {
		t.Errorf("SuppressedCount のデフォルト = %d, want 0", e.SuppressedCount)
	}
	if e.AgentID != nil {
		t.Errorf("AgentID のデフォルトは nil であるべき")
	}
	if e.ExpiresAt != nil {
		t.Errorf("ExpiresAt のデフォルトは nil であるべき")
	}
}

// TestSuppressionRuleEntry_PatternAndMatchField はパターンとマッチフィールドの設定を確認する
func TestSuppressionRuleEntry_PatternAndMatchField(t *testing.T) {
	agentID := "agent-001"
	e := SuppressionRuleEntry{
		Name:            "PowerShell Noise",
		Pattern:         "powershell.exe",
		MatchField:      "title",
		AgentID:         &agentID,
		SeverityMax:     4,
		Enabled:         true,
		SuppressedCount: 100,
	}
	if e.Pattern != "powershell.exe" {
		t.Errorf("Pattern = %q, want \"powershell.exe\"", e.Pattern)
	}
	if e.MatchField != "title" {
		t.Errorf("MatchField = %q, want \"title\"", e.MatchField)
	}
	if e.AgentID == nil || *e.AgentID != "agent-001" {
		t.Errorf("AgentID = %v, want \"agent-001\"", e.AgentID)
	}
	if !e.Enabled {
		t.Error("Enabled = false, want true")
	}
	if e.SuppressedCount != 100 {
		t.Errorf("SuppressedCount = %d, want 100", e.SuppressedCount)
	}
}
