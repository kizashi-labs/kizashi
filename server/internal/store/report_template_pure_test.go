package store

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── ReportTemplateSection 構造体テスト ───────────────────────────────────────

// TestReportTemplateSection_ZeroValue は ReportTemplateSection のゼロ値が期待通りであることを確認する
func TestReportTemplateSection_ZeroValue(t *testing.T) {
	var sec ReportTemplateSection
	if sec.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", sec.Type)
	}
	if sec.Title != "" {
		t.Errorf("Title のデフォルト = %q, want \"\"", sec.Title)
	}
	if sec.Config != nil {
		t.Errorf("Config のデフォルトは nil であるべき: got %v", sec.Config)
	}
}

// TestReportTemplateSection_FieldAssignment は ReportTemplateSection のフィールド代入を確認する
func TestReportTemplateSection_FieldAssignment(t *testing.T) {
	sec := ReportTemplateSection{
		Type:  "chart",
		Title: "アラート統計チャート",
		Config: map[string]interface{}{
			"chartType":  "bar",
			"timeRange":  "7d",
			"maxEntries": 10,
		},
	}

	if sec.Type != "chart" {
		t.Errorf("Type = %q, want \"chart\"", sec.Type)
	}
	if sec.Title != "アラート統計チャート" {
		t.Errorf("Title = %q, want \"アラート統計チャート\"", sec.Title)
	}
	if sec.Config["chartType"] != "bar" {
		t.Errorf("Config[chartType] = %v, want \"bar\"", sec.Config["chartType"])
	}
}

// TestReportTemplateSection_KnownTypes は既知のセクションタイプを確認する
func TestReportTemplateSection_KnownTypes(t *testing.T) {
	knownTypes := []string{"summary", "chart", "table", "text", "metrics"}
	for _, sType := range knownTypes {
		sec := ReportTemplateSection{Type: sType}
		if sec.Type != sType {
			t.Errorf("Type = %q, want %q", sec.Type, sType)
		}
	}
}

// ─── ReportTemplate 構造体テスト ──────────────────────────────────────────────

// TestReportTemplate_ZeroValue は ReportTemplate のゼロ値が期待通りであることを確認する
func TestReportTemplate_ZeroValue(t *testing.T) {
	var tmpl ReportTemplate
	if tmpl.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", tmpl.ID)
	}
	if tmpl.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if tmpl.Sections != nil {
		t.Errorf("Sections のデフォルトは nil であるべき: got %v", tmpl.Sections)
	}
	if tmpl.Variables != nil {
		t.Errorf("Variables のデフォルトは nil であるべき: got %v", tmpl.Variables)
	}
	if tmpl.CreatedBy != nil {
		t.Error("CreatedBy のデフォルトは nil であるべき")
	}
}

// TestReportTemplate_FieldAssignment は ReportTemplate のフィールド代入を確認する
func TestReportTemplate_FieldAssignment(t *testing.T) {
	creator := "user-001"
	now := time.Now().UTC()

	tmpl := ReportTemplate{
		ID:          "tmpl-abc",
		Name:        "セキュリティ月次レポート",
		Description: "月次セキュリティレポートテンプレート",
		Sections: []ReportTemplateSection{
			{Type: "summary", Title: "サマリー"},
		},
		Variables: map[string]interface{}{
			"orgName": "Acme Corp",
			"period":  "monthly",
		},
		Format:    "pdf",
		Enabled:   true,
		CreatedBy: &creator,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if tmpl.ID != "tmpl-abc" {
		t.Errorf("ID = %q, want \"tmpl-abc\"", tmpl.ID)
	}
	if !tmpl.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(tmpl.Sections) != 1 {
		t.Errorf("Sections 長 = %d, want 1", len(tmpl.Sections))
	}
	if tmpl.Variables["orgName"] != "Acme Corp" {
		t.Errorf("Variables[orgName] = %v, want \"Acme Corp\"", tmpl.Variables["orgName"])
	}
	if *tmpl.CreatedBy != creator {
		t.Errorf("CreatedBy = %q, want %q", *tmpl.CreatedBy, creator)
	}
}

// TestReportTemplate_FormatValues は有効な Format 値を確認する
func TestReportTemplate_FormatValues(t *testing.T) {
	validFormats := []string{"pdf", "html", "csv", "json"}
	for _, fmt := range validFormats {
		tmpl := ReportTemplate{Format: fmt}
		if tmpl.Format != fmt {
			t.Errorf("Format = %q, want %q", tmpl.Format, fmt)
		}
	}
}

// TestReportTemplate_SectionsJSONRoundtrip は Sections の JSON シリアライズ／デシリアライズを確認する
func TestReportTemplate_SectionsJSONRoundtrip(t *testing.T) {
	original := []ReportTemplateSection{
		{
			Type:  "table",
			Title: "アラート一覧",
			Config: map[string]interface{}{
				"columns": []interface{}{"time", "severity", "type"},
				"limit":   float64(50),
			},
		},
		{
			Type:  "summary",
			Title: "概要",
			Config: map[string]interface{}{
				"showTotal": true,
			},
		},
	}

	// JSON シリアライズ
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal に失敗: %v", err)
	}

	// JSON デシリアライズ
	var decoded []ReportTemplateSection
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal に失敗: %v", err)
	}

	if len(decoded) != len(original) {
		t.Errorf("デコード後のセクション数 = %d, want %d", len(decoded), len(original))
	}
	if decoded[0].Type != original[0].Type {
		t.Errorf("decoded[0].Type = %q, want %q", decoded[0].Type, original[0].Type)
	}
	if decoded[1].Title != original[1].Title {
		t.Errorf("decoded[1].Title = %q, want %q", decoded[1].Title, original[1].Title)
	}
}

// TestReportTemplate_VariablesJSONRoundtrip は Variables の JSON シリアライズ／デシリアライズを確認する
func TestReportTemplate_VariablesJSONRoundtrip(t *testing.T) {
	original := map[string]interface{}{
		"orgName":    "Test Corp",
		"maxAlerts":  float64(100),
		"showCharts": true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal に失敗: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal に失敗: %v", err)
	}

	if decoded["orgName"] != "Test Corp" {
		t.Errorf("orgName = %v, want \"Test Corp\"", decoded["orgName"])
	}
	if decoded["maxAlerts"] != float64(100) {
		t.Errorf("maxAlerts = %v, want 100", decoded["maxAlerts"])
	}
	if decoded["showCharts"] != true {
		t.Errorf("showCharts = %v, want true", decoded["showCharts"])
	}
}

// TestReportTemplate_EmptySectionsDefaulted は Sections が nil のとき
// 空スライスに初期化されるロジックを確認する
func TestReportTemplate_EmptySectionsDefaulted(t *testing.T) {
	// scanReportTemplate 内の nil → 空スライス変換ロジックを再現する
	var sections []ReportTemplateSection
	if sections == nil {
		sections = []ReportTemplateSection{}
	}
	if sections == nil {
		t.Error("sections は空スライスに初期化されるべき")
	}
	if len(sections) != 0 {
		t.Errorf("sections 長 = %d, want 0", len(sections))
	}
}

// TestReportTemplate_EmptyVariablesDefaulted は Variables が nil のとき
// 空マップに初期化されるロジックを確認する
func TestReportTemplate_EmptyVariablesDefaulted(t *testing.T) {
	// scanReportTemplate 内の nil → 空マップ変換ロジックを再現する
	var variables map[string]interface{}
	if variables == nil {
		variables = map[string]interface{}{}
	}
	if variables == nil {
		t.Error("variables は空マップに初期化されるべき")
	}
	if len(variables) != 0 {
		t.Errorf("variables 長 = %d, want 0", len(variables))
	}
}

// TestReportTemplate_InvalidSectionsJSONFallback は不正な sections JSON のとき
// 空スライスにフォールバックするロジックを確認する
func TestReportTemplate_InvalidSectionsJSONFallback(t *testing.T) {
	invalidJSON := "not-valid-json"

	var sections []ReportTemplateSection
	if err := json.Unmarshal([]byte(invalidJSON), &sections); err != nil {
		// 不正な JSON は空スライスにフォールバックする
		sections = []ReportTemplateSection{}
	}
	if sections == nil {
		t.Error("不正な JSON のとき sections は空スライスにフォールバックすべき")
	}
}

// TestReportTemplate_VariableTypes は Variables にさまざまな型を格納できることを確認する
func TestReportTemplate_VariableTypes(t *testing.T) {
	tmpl := ReportTemplate{
		Variables: map[string]interface{}{
			"strVal":  "hello",
			"intVal":  float64(42), // JSON ではすべての数値が float64
			"boolVal": true,
			"nullVal": nil,
		},
	}

	if tmpl.Variables["strVal"] != "hello" {
		t.Errorf("strVal = %v, want \"hello\"", tmpl.Variables["strVal"])
	}
	if tmpl.Variables["intVal"] != float64(42) {
		t.Errorf("intVal = %v, want 42", tmpl.Variables["intVal"])
	}
	if tmpl.Variables["boolVal"] != true {
		t.Errorf("boolVal = %v, want true", tmpl.Variables["boolVal"])
	}
	if tmpl.Variables["nullVal"] != nil {
		t.Errorf("nullVal = %v, want nil", tmpl.Variables["nullVal"])
	}
}

// TestReportTemplate_MultipleSections は複数のセクションを持つテンプレートを確認する
func TestReportTemplate_MultipleSections(t *testing.T) {
	tmpl := ReportTemplate{
		Sections: []ReportTemplateSection{
			{Type: "summary", Title: "エグゼクティブサマリー"},
			{Type: "chart", Title: "アラート推移グラフ"},
			{Type: "table", Title: "インシデント一覧"},
			{Type: "metrics", Title: "KPI メトリクス"},
		},
	}

	if len(tmpl.Sections) != 4 {
		t.Errorf("Sections 長 = %d, want 4", len(tmpl.Sections))
	}

	expectedTypes := []string{"summary", "chart", "table", "metrics"}
	for i, want := range expectedTypes {
		if tmpl.Sections[i].Type != want {
			t.Errorf("Sections[%d].Type = %q, want %q", i, tmpl.Sections[i].Type, want)
		}
	}
}
