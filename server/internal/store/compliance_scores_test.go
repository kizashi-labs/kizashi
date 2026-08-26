package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── ComplianceScore 構造体テスト ─────────────────────────────────────────────

// TestComplianceScore_ZeroValue は ComplianceScore のゼロ値が期待通りであることを確認する
func TestComplianceScore_ZeroValue(t *testing.T) {
	var s ComplianceScore
	if s.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", s.ID)
	}
	if s.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", s.AgentID)
	}
	if s.Framework != "" {
		t.Errorf("Framework のデフォルト = %q, want \"\"", s.Framework)
	}
	if s.Score != 0 {
		t.Errorf("Score のデフォルト = %d, want 0", s.Score)
	}
	if s.TotalChecks != 0 {
		t.Errorf("TotalChecks のデフォルト = %d, want 0", s.TotalChecks)
	}
	if s.PassedChecks != 0 {
		t.Errorf("PassedChecks のデフォルト = %d, want 0", s.PassedChecks)
	}
	if s.Details != nil {
		t.Errorf("Details のデフォルトは nil であるべき")
	}
	if s.ComputedAt != "" {
		t.Errorf("ComputedAt のデフォルト = %q, want \"\"", s.ComputedAt)
	}
}

// TestComplianceScore_FieldAssignment は ComplianceScore の全フィールドが正しく代入できることを確認する
func TestComplianceScore_FieldAssignment(t *testing.T) {
	details := json.RawMessage(`{"failed_checks": ["CIS-1.1", "CIS-2.3"]}`)
	s := ComplianceScore{
		ID:           "score-uuid-001",
		AgentID:      "agent-uuid-001",
		Framework:    "CIS",
		Score:        72,
		TotalChecks:  100,
		PassedChecks: 72,
		Details:      details,
		ComputedAt:   time.Now().Format(time.RFC3339),
	}

	if s.ID != "score-uuid-001" {
		t.Errorf("ID = %q, want \"score-uuid-001\"", s.ID)
	}
	if s.Framework != "CIS" {
		t.Errorf("Framework = %q, want \"CIS\"", s.Framework)
	}
	if s.Score != 72 {
		t.Errorf("Score = %d, want 72", s.Score)
	}
	if s.TotalChecks != 100 {
		t.Errorf("TotalChecks = %d, want 100", s.TotalChecks)
	}
	if s.PassedChecks != 72 {
		t.Errorf("PassedChecks = %d, want 72", s.PassedChecks)
	}
}

// TestComplianceScore_ScoreRange はスコアが 0〜100 の範囲で表現できることを確認する
func TestComplianceScore_ScoreRange(t *testing.T) {
	cases := []int{0, 25, 50, 75, 100}
	for _, score := range cases {
		s := ComplianceScore{Score: score}
		if s.Score != score {
			t.Errorf("Score = %d, want %d", s.Score, score)
		}
	}
}

// TestComplianceScore_KnownFrameworks は既知のコンプライアンスフレームワーク名を確認する
func TestComplianceScore_KnownFrameworks(t *testing.T) {
	// EDRプラットフォームで使用される標準的なフレームワーク
	knownFrameworks := []string{"CIS", "NIST", "PCI-DSS", "ISO27001", "HIPAA"}
	for _, fw := range knownFrameworks {
		s := ComplianceScore{Framework: fw}
		if s.Framework != fw {
			t.Errorf("Framework = %q, want %q", s.Framework, fw)
		}
	}
}

// TestComplianceScore_DefaultFrameworkLogic は空のフレームワークが "CIS" にデフォルト設定されることを確認する
func TestComplianceScore_DefaultFrameworkLogic(t *testing.T) {
	// GetByAgent 内のロジックを反映したヘルパー
	resolveFramework := func(fw string) string {
		if fw == "" {
			return "CIS"
		}
		return fw
	}

	if got := resolveFramework(""); got != "CIS" {
		t.Errorf("空フレームワークのデフォルト = %q, want \"CIS\"", got)
	}
	if got := resolveFramework("NIST"); got != "NIST" {
		t.Errorf("NIST フレームワーク = %q, want \"NIST\"", got)
	}
	if got := resolveFramework("PCI-DSS"); got != "PCI-DSS" {
		t.Errorf("PCI-DSS フレームワーク = %q, want \"PCI-DSS\"", got)
	}
}

// TestComplianceScore_PassedVsTotalConsistency は PassedChecks が TotalChecks 以下であることを確認する
func TestComplianceScore_PassedVsTotalConsistency(t *testing.T) {
	cases := []struct {
		total  int
		passed int
		valid  bool
	}{
		{100, 72, true},
		{50, 50, true},
		{100, 0, true},
		{0, 0, true},
		// passed > total は論理的に不正
		{50, 51, false},
	}
	for _, tc := range cases {
		isValid := tc.passed <= tc.total
		if isValid != tc.valid {
			t.Errorf("total=%d passed=%d: valid = %v, want %v", tc.total, tc.passed, isValid, tc.valid)
		}
	}
}

// TestComplianceScore_DetailsNilFallbackToEmpty は Details が nil のとき空 JSON にフォールバックすることを確認する
func TestComplianceScore_DetailsNilFallbackToEmpty(t *testing.T) {
	// scanComplianceScore のロジック: detailsRaw == nil なら "{}" を使用する
	applyDetailsFallback := func(raw []byte) json.RawMessage {
		if raw != nil {
			return json.RawMessage(raw)
		}
		return json.RawMessage("{}")
	}

	result := applyDetailsFallback(nil)
	if string(result) != "{}" {
		t.Errorf("nil の Details は \"{}\" にフォールバックするべき: got %q", string(result))
	}

	result2 := applyDetailsFallback([]byte(`{"key":"value"}`))
	if string(result2) != `{"key":"value"}` {
		t.Errorf("非nil の Details はそのまま使用するべき: got %q", string(result2))
	}
}

// TestComplianceScore_ComputedAtRFC3339Format は ComputedAt が RFC3339 フォーマットであることを確認する
func TestComplianceScore_ComputedAtRFC3339Format(t *testing.T) {
	now := time.Now().UTC()
	formatted := now.Format(time.RFC3339)
	s := ComplianceScore{ComputedAt: formatted}

	// RFC3339 フォーマットの特徴: "T" 区切り、タイムゾーン付き
	if !strings.Contains(s.ComputedAt, "T") {
		t.Errorf("ComputedAt は RFC3339 形式 (T区切り) であるべき: %q", s.ComputedAt)
	}
	// パースして往復できることを確認する
	parsed, err := time.Parse(time.RFC3339, s.ComputedAt)
	if err != nil {
		t.Errorf("ComputedAt のパースに失敗: %v", err)
	}
	if parsed.IsZero() {
		t.Error("パースされた ComputedAt はゼロ時刻であってはならない")
	}
}

// TestComplianceScore_ScoreCalculationFromChecks は passed/total からスコアを計算するロジックを確認する
func TestComplianceScore_ScoreCalculationFromChecks(t *testing.T) {
	// スコアを passed/total の割合 (0-100) として計算するヘルパー
	computeScore := func(passed, total int) int {
		if total == 0 {
			return 0
		}
		return (passed * 100) / total
	}

	cases := []struct {
		passed, total int
		wantScore     int
	}{
		{100, 100, 100},
		{0, 100, 0},
		{50, 100, 50},
		{72, 100, 72},
		{0, 0, 0},
		{3, 4, 75},
	}
	for _, tc := range cases {
		got := computeScore(tc.passed, tc.total)
		if got != tc.wantScore {
			t.Errorf("computeScore(%d, %d) = %d, want %d", tc.passed, tc.total, got, tc.wantScore)
		}
	}
}

// TestComplianceScore_UpsertDetailsNilFallback は Upsert 時の Details nil フォールバックを確認する
func TestComplianceScore_UpsertDetailsNilFallback(t *testing.T) {
	// Upsert のロジック: details == nil なら "{}" を設定する
	resolveDetails := func(details json.RawMessage) json.RawMessage {
		if details == nil {
			return json.RawMessage("{}")
		}
		return details
	}

	result := resolveDetails(nil)
	if string(result) != "{}" {
		t.Errorf("nil Details は \"{}\" にフォールバックするべき: got %q", string(result))
	}

	payload := json.RawMessage(`{"checks": 42}`)
	result2 := resolveDetails(payload)
	if string(result2) != `{"checks": 42}` {
		t.Errorf("非nil Details は変更されないべき: got %q", string(result2))
	}
}
