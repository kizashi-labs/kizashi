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

// nil の節・変数が、空の値として出ること。**本物を呼びます。**
//
// 以前ここには `var sections []T; if sections == nil { sections = []T{} }`
// を**検査の本文で実行して**、そのあと nil でないことを確かめる2本が
// ありました。Go の代入を試しているだけで、製品を1行も通りません。
//
// **なぜ空スライスにするのか**: nil は JSON で `null` に、空スライスは
// `[]` になります。画面が `.map()` を呼ぶと、`null` では落ちます ——
// テンプレート一覧が丸ごと出なくなります。
func TestScanReportTemplateTurnsNilIntoEmpty(t *testing.T) {
	row := &fakeTemplateRow{sections: "null", variables: "null"}
	got, err := scanReportTemplate(row)
	if err != nil {
		t.Fatalf("scanReportTemplate: %v", err)
	}
	if got.Sections == nil {
		t.Error("Sections が nil です。**JSON で null になり、画面の .map() が落ちます**")
	}
	if len(got.Sections) != 0 {
		t.Errorf("Sections = %v, want 空", got.Sections)
	}
	if got.Variables == nil {
		t.Error("Variables が nil です")
	}
	if len(got.Variables) != 0 {
		t.Errorf("Variables = %v, want 空", got.Variables)
	}

	// 中身のあるものは、そのまま残ること。
	row = &fakeTemplateRow{
		sections:  `[{"title":"概要"}]`,
		variables: `{"period":"7d"}`,
	}
	got, err = scanReportTemplate(row)
	if err != nil {
		t.Fatalf("scanReportTemplate: %v", err)
	}
	if len(got.Sections) != 1 || len(got.Variables) != 1 {
		t.Errorf("中身が失われています: sections=%v variables=%v",
			got.Sections, got.Variables)
	}
}

// 読めない JSON は、**空として通しません。**
//
// 節が空のテンプレートは、白紙のレポートを出します —— 「節が無い」と
// 「節を読めなかった」は別の事実です。
func TestScanReportTemplateRefusesUnreadableJSON(t *testing.T) {
	for _, row := range []*fakeTemplateRow{
		{sections: "not-json", variables: "{}"},
		{sections: "[]", variables: "not-json"},
	} {
		if _, err := scanReportTemplate(row); err == nil {
			t.Errorf("読めない JSON を通しています: %+v", row)
		}
	}
}

// fakeTemplateRow feeds scanReportTemplate without a database.
type fakeTemplateRow struct {
	sections  string
	variables string
}

func (f *fakeTemplateRow) Scan(dest ...interface{}) error {
	vals := []interface{}{
		"id-1", "名前", "説明", f.sections, f.variables, "pdf", true, "user-1",
		time.Now(), time.Now(),
	}
	for i := range dest {
		if i >= len(vals) {
			break
		}
		switch d := dest[i].(type) {
		case *string:
			if v, ok := vals[i].(string); ok {
				*d = v
			}
		case *bool:
			if v, ok := vals[i].(bool); ok {
				*d = v
			}
		case *time.Time:
			if v, ok := vals[i].(time.Time); ok {
				*d = v
			}
		}
	}
	return nil
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
