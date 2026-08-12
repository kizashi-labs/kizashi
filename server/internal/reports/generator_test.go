package reports

import (
	"context"
	"strings"
	"testing"
)

// ─── NewGenerator ─────────────────────────────────────────────────────────────

func TestNewGenerator_NotNil(t *testing.T) {
	g := NewGenerator(nil)
	if g == nil {
		t.Fatal("NewGenerator は nil を返すべきではありません")
	}
}

// ─── GetTemplates ─────────────────────────────────────────────────────────────

func TestGetTemplates_NotEmpty(t *testing.T) {
	templates := GetTemplates()
	if len(templates) == 0 {
		t.Fatal("GetTemplates: テンプレートが空です")
	}
}

func TestGetTemplates_HasExecutiveSummary(t *testing.T) {
	templates := GetTemplates()
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "executive_summary" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetTemplates: executive_summary テンプレートが見つかりません")
	}
}

func TestGetTemplates_HasComplianceReport(t *testing.T) {
	templates := GetTemplates()
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "compliance_report" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetTemplates: compliance_report テンプレートが見つかりません")
	}
}

func TestGetTemplates_HasIncidentReport(t *testing.T) {
	templates := GetTemplates()
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "incident_report" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetTemplates: incident_report テンプレートが見つかりません")
	}
}

func TestGetTemplates_HasThreatSummary(t *testing.T) {
	templates := GetTemplates()
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "threat_summary" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetTemplates: threat_summary テンプレートが見つかりません")
	}
}

func TestGetTemplates_AllHaveNames(t *testing.T) {
	for _, tmpl := range GetTemplates() {
		if tmpl.Name == "" {
			t.Errorf("テンプレート %q の Name が空です", tmpl.ID)
		}
	}
}

func TestGetTemplates_AllHaveFields(t *testing.T) {
	for _, tmpl := range GetTemplates() {
		if len(tmpl.Fields) == 0 {
			t.Errorf("テンプレート %q の Fields が空です", tmpl.ID)
		}
	}
}

// ─── ToCSV ────────────────────────────────────────────────────────────────────

func TestToCSV_NilData_ReturnsEmpty(t *testing.T) {
	g := NewGenerator(nil)
	out, err := g.ToCSV(nil)
	if err != nil {
		t.Fatalf("ToCSV(nil): 予期しないエラー: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("ToCSV(nil): got %d bytes, want 0", len(out))
	}
}

func TestToCSV_SimpleStruct_ContainsHeader(t *testing.T) {
	g := NewGenerator(nil)
	data := map[string]interface{}{"key1": "value1"}
	out, err := g.ToCSV(data)
	if err != nil {
		t.Fatalf("ToCSV: 予期しないエラー: %v", err)
	}
	if !strings.Contains(string(out), "field") {
		t.Errorf("ToCSV: ヘッダー 'field' が含まれていません: %s", out)
	}
	if !strings.Contains(string(out), "value") {
		t.Errorf("ToCSV: ヘッダー 'value' が含まれていません: %s", out)
	}
}

func TestToCSV_ContainsKey(t *testing.T) {
	g := NewGenerator(nil)
	data := map[string]interface{}{"mykey": "myvalue"}
	out, err := g.ToCSV(data)
	if err != nil {
		t.Fatalf("ToCSV: 予期しないエラー: %v", err)
	}
	if !strings.Contains(string(out), "mykey") {
		t.Errorf("ToCSV: キー 'mykey' が含まれていません: %s", out)
	}
}

// ─── flattenValue ─────────────────────────────────────────────────────────────

func TestFlattenValue_Nil_ReturnsEmpty(t *testing.T) {
	if got := flattenValue(nil); got != "" {
		t.Errorf("flattenValue(nil): got %q, want empty", got)
	}
}

func TestFlattenValue_String_ReturnsString(t *testing.T) {
	if got := flattenValue("hello"); got != "hello" {
		t.Errorf("flattenValue(string): got %q, want hello", got)
	}
}

func TestFlattenValue_Float64_FormattedAsDecimal(t *testing.T) {
	got := flattenValue(float64(3.14))
	if got != "3.14" {
		t.Errorf("flattenValue(float64): got %q, want 3.14", got)
	}
}

func TestFlattenValue_BoolTrue_ReturnsTrue(t *testing.T) {
	if got := flattenValue(true); got != "true" {
		t.Errorf("flattenValue(true): got %q, want true", got)
	}
}

func TestFlattenValue_BoolFalse_ReturnsFalse(t *testing.T) {
	if got := flattenValue(false); got != "false" {
		t.Errorf("flattenValue(false): got %q, want false", got)
	}
}

func TestFlattenValue_Map_ReturnsJSON(t *testing.T) {
	m := map[string]interface{}{"a": "b"}
	got := flattenValue(m)
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Errorf("flattenValue(map): got %q, want JSON with a/b", got)
	}
}

func TestFlattenValue_EmptySlice_ReturnsBrackets(t *testing.T) {
	got := flattenValue([]interface{}{})
	if got != "[]" {
		t.Errorf("flattenValue([]): got %q, want []", got)
	}
}

func TestFlattenValue_NonEmptySlice_ReturnsJSON(t *testing.T) {
	got := flattenValue([]interface{}{"a", "b"})
	if !strings.Contains(got, "a") {
		t.Errorf("flattenValue(slice): got %q", got)
	}
}

func TestFlattenValue_Int_FormattedAsString(t *testing.T) {
	// int は default ケースに落ちるので fmt.Sprintf
	got := flattenValue(42)
	if got != "42" {
		t.Errorf("flattenValue(int): got %q, want 42", got)
	}
}

// ─── Generate (unsupported type) ─────────────────────────────────────────────

func TestGenerate_UnknownType_ReturnsError(t *testing.T) {
	g := NewGenerator(nil)
	_, err := g.Generate(context.TODO(), &ReportSpec{Type: "unknown_type"})
	if err == nil {
		t.Error("未知レポートタイプはエラーを返すべきです")
	}
}
