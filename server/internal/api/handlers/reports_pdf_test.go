package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// typeLabel のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestTypeLabel_KnownTypes(t *testing.T) {
	// 既知のレポートタイプが正しいラベルに変換されることを確認
	tests := []struct {
		input string
		want  string
	}{
		{"alert_summary", "Alert Summary"},
		{"agent_status", "Agent Status"},
		{"threat_report", "Threat Report"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := typeLabel(tc.input); got != tc.want {
				t.Errorf("typeLabel(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestTypeLabel_UnknownType_ReturnsAsIs(t *testing.T) {
	// 未知のタイプはそのまま返される
	input := "custom_report"
	if got := typeLabel(input); got != input {
		t.Errorf("typeLabel(%q) = %q, want %q (入力そのまま)", input, got, input)
	}
}

func TestTypeLabel_EmptyString(t *testing.T) {
	// 空文字列の場合は空文字列が返される
	if got := typeLabel(""); got != "" {
		t.Errorf("typeLabel(\"\") = %q, want \"\"", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// titleForType のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestTitleForType_KnownTypes(t *testing.T) {
	// 既知のレポートタイプが正しいタイトルに変換されることを確認
	tests := []struct {
		input string
		want  string
	}{
		{"executive_summary", "Executive Security Summary"},
		{"compliance_report", "Compliance Status Report"},
		{"incident_report", "Incident Report"},
		{"threat_summary", "Threat Intelligence Summary"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := titleForType(tc.input); got != tc.want {
				t.Errorf("titleForType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestTitleForType_UnknownType_DefaultTitle(t *testing.T) {
	// 未知のタイプはデフォルトタイトルが返される
	want := "Security Report"
	if got := titleForType("unknown_type"); got != want {
		t.Errorf("titleForType(\"unknown_type\") = %q, want %q", got, want)
	}
}

func TestTitleForType_EmptyString_DefaultTitle(t *testing.T) {
	// 空文字列もデフォルトタイトルが返される
	want := "Security Report"
	if got := titleForType(""); got != want {
		t.Errorf("titleForType(\"\") = %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// pdfEscape のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestPDFEscape_PlainText(t *testing.T) {
	// 特殊文字のないテキストはそのまま返される
	input := "Hello World"
	if got := pdfEscape(input); got != input {
		t.Errorf("pdfEscape(%q) = %q, want %q", input, got, input)
	}
}

func TestPDFEscape_Backslash(t *testing.T) {
	// バックスラッシュがエスケープされる
	input := `C:\Users\admin`
	want := `C:\\Users\\admin`
	if got := pdfEscape(input); got != want {
		t.Errorf("pdfEscape(%q) = %q, want %q", input, got, want)
	}
}

func TestPDFEscape_Parentheses(t *testing.T) {
	// 括弧がエスケープされる
	input := "(value)"
	want := `\(value\)`
	if got := pdfEscape(input); got != want {
		t.Errorf("pdfEscape(%q) = %q, want %q", input, got, want)
	}
}

func TestPDFEscape_BackslashBeforeParenthesis(t *testing.T) {
	// バックスラッシュと括弧が共存している場合の順序を確認
	// バックスラッシュを先にエスケープしないと誤った結果になる
	input := `\(`
	want := `\\\(`
	if got := pdfEscape(input); got != want {
		t.Errorf("pdfEscape(%q) = %q, want %q", input, got, want)
	}
}

func TestPDFEscape_EmptyString(t *testing.T) {
	// 空文字列はそのまま
	if got := pdfEscape(""); got != "" {
		t.Errorf("pdfEscape(\"\") = %q, want \"\"", got)
	}
}

func TestPDFEscape_MixedSpecialChars(t *testing.T) {
	// バックスラッシュ・開き括弧・閉じ括弧が混在するケース
	input := `(a\b)`
	want := `\(a\\b\)`
	if got := pdfEscape(input); got != want {
		t.Errorf("pdfEscape(%q) = %q, want %q", input, got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sanitizeLine のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestSanitizeLine_PlainASCII(t *testing.T) {
	// 通常のASCII文字列はそのまま返される
	input := "Hello, World! 123"
	if got := sanitizeLine(input); got != input {
		t.Errorf("sanitizeLine(%q) = %q, want %q", input, got, input)
	}
}

func TestSanitizeLine_NonPrintableRemoved(t *testing.T) {
	// 印字不可能文字（制御文字など）は除去される
	input := "hello\x00world\x01test"
	want := "helloworldtest"
	if got := sanitizeLine(input); got != want {
		t.Errorf("sanitizeLine(%q) = %q, want %q", input, got, want)
	}
}

func TestSanitizeLine_TabExpandedToSpaces(t *testing.T) {
	// タブ文字は2スペースに展開される
	input := "col1\tcol2"
	want := "col1  col2"
	if got := sanitizeLine(input); got != want {
		t.Errorf("sanitizeLine(%q) = %q, want %q", input, got, want)
	}
}

func TestSanitizeLine_LongLineTruncated(t *testing.T) {
	// 100文字を超える行は省略記号付きで切り詰められる
	input := strings.Repeat("A", 150)
	got := sanitizeLine(input)
	if len(got) > 100 {
		t.Errorf("sanitizeLine: 100文字超えています (len=%d)", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("sanitizeLine: 省略記号で終わっていません: got %q", got[len(got)-5:])
	}
}

func TestSanitizeLine_ExactlyAtLimit(t *testing.T) {
	// 100文字ちょうどの場合は切り詰めなし
	input := strings.Repeat("B", 100)
	got := sanitizeLine(input)
	if got != input {
		t.Errorf("sanitizeLine(100文字) = %q, want %q", got, input)
	}
}

func TestSanitizeLine_JapaneseCharactersRemoved(t *testing.T) {
	// 日本語などのマルチバイト文字はASCII範囲外なので除去される
	input := "hello世界test"
	want := "hellotest"
	if got := sanitizeLine(input); got != want {
		t.Errorf("sanitizeLine(%q) = %q, want %q", input, got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// flattenContent のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestFlattenContent_SimpleMap(t *testing.T) {
	// マップの単純なフラット化
	v := map[string]interface{}{
		"key": "value",
	}
	var lines []string
	flattenContent("", v, &lines, 0)
	if len(lines) == 0 {
		t.Fatal("flattenContent: マップが空のスライスを返しました")
	}
	// "key: value" のような行が1行含まれるはず
	found := false
	for _, l := range lines {
		if strings.Contains(l, "key") && strings.Contains(l, "value") {
			found = true
		}
	}
	if !found {
		t.Errorf("flattenContent: キーと値が出力に含まれていません: %v", lines)
	}
}

func TestFlattenContent_SliceItems(t *testing.T) {
	// スライスの各要素が展開される
	v := []interface{}{"item1", "item2", "item3"}
	var lines []string
	flattenContent("", v, &lines, 0)
	if len(lines) != 3 {
		t.Errorf("flattenContent: 3行期待, got %d行: %v", len(lines), lines)
	}
}

func TestFlattenContent_LargeSliceLimited(t *testing.T) {
	// 25件を超えるスライスには省略メッセージが付く
	items := make([]interface{}, 30)
	for i := range items {
		items[i] = i
	}
	var lines []string
	flattenContent("", items, &lines, 0)
	// 25行 + 省略行 = 26行
	if len(lines) != 26 {
		t.Errorf("大きなスライス: 26行期待, got %d行", len(lines))
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "more") && !strings.Contains(last, "...") {
		t.Errorf("省略メッセージが含まれていません: %q", last)
	}
}

func TestFlattenContent_DepthLimit(t *testing.T) {
	// 深さ5を超えると再帰が止まる
	// depth=5 で呼び出すと行が追加されないことを確認
	var lines []string
	flattenContent("", map[string]interface{}{"x": "y"}, &lines, 5)
	if len(lines) != 0 {
		t.Errorf("深さ5以上では行を追加しないはずですが %d 行追加されました", len(lines))
	}
}

func TestFlattenContent_NestedMap(t *testing.T) {
	// ネストされたマップが展開される
	v := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": "val",
		},
	}
	var lines []string
	flattenContent("", v, &lines, 0)
	if len(lines) == 0 {
		t.Fatal("ネストされたマップが何も出力しませんでした")
	}
}
