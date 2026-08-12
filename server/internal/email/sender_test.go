package email

import (
	"strings"
	"testing"
)

// ─── renderTemplate ───────────────────────────────────────────────────────────

func TestRenderTemplate_BasicSubstitution(t *testing.T) {
	tmpl := "Hello {{.Name}}, your URL is {{.URL}}"
	data := map[string]string{"Name": "Alice", "URL": "https://example.com"}
	got := renderTemplate(tmpl, data)
	if !strings.Contains(got, "Alice") {
		t.Errorf("置換後に 'Alice' が含まれるべき: %q", got)
	}
	if !strings.Contains(got, "https://example.com") {
		t.Errorf("置換後に URL が含まれるべき: %q", got)
	}
}

func TestRenderTemplate_MissingKey(t *testing.T) {
	// Goのtemplateはmapにキーが存在しない場合空文字列を返す
	tmpl := "Hello {{.MissingKey}}"
	data := map[string]string{}
	got := renderTemplate(tmpl, data)
	// エラーにならず、空文字列で置換される
	if got == "" {
		t.Error("テンプレートは空でなく部分的に描画されるべき")
	}
}

func TestRenderTemplate_InvalidTemplate(t *testing.T) {
	// 無効なテンプレート構文 → 空文字列を返す
	tmpl := "{{.Name" // 閉じ括弧なし
	data := map[string]string{"Name": "test"}
	got := renderTemplate(tmpl, data)
	if got != "" {
		t.Errorf("無効なテンプレートは空文字列を返すべき: got %q", got)
	}
}

func TestRenderTemplate_EmptyData(t *testing.T) {
	tmpl := "No placeholders here."
	data := map[string]string{}
	got := renderTemplate(tmpl, data)
	if got != "No placeholders here." {
		t.Errorf("プレースホルダーなしは元のテキストをそのまま返すべき: got %q", got)
	}
}

func TestRenderTemplate_MultipleKeys(t *testing.T) {
	tmpl := "{{.A}} + {{.B}} = {{.C}}"
	data := map[string]string{"A": "1", "B": "2", "C": "3"}
	got := renderTemplate(tmpl, data)
	want := "1 + 2 = 3"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ─── renderTemplateDynamic ────────────────────────────────────────────────────

func TestRenderTemplateDynamic_WithStruct(t *testing.T) {
	type Data struct {
		Title   string
		Message string
	}
	tmpl := "{{.Title}}: {{.Message}}"
	data := Data{Title: "Alert", Message: "Threat detected"}
	got := renderTemplateDynamic(tmpl, data)
	if !strings.Contains(got, "Alert") {
		t.Errorf("構造体フィールドが描画されるべき: got %q", got)
	}
	if !strings.Contains(got, "Threat detected") {
		t.Errorf("メッセージが描画されるべき: got %q", got)
	}
}

func TestRenderTemplateDynamic_WithMap(t *testing.T) {
	tmpl := "{{index . \"key\"}}"
	data := map[string]interface{}{"key": "value123"}
	got := renderTemplateDynamic(tmpl, data)
	if !strings.Contains(got, "value123") {
		t.Errorf("mapの値が描画されるべき: got %q", got)
	}
}

func TestRenderTemplateDynamic_InvalidTemplate(t *testing.T) {
	got := renderTemplateDynamic("{{.Unclosed", "data")
	if got != "" {
		t.Errorf("無効なテンプレートは空文字列を返すべき: got %q", got)
	}
}

func TestRenderTemplateDynamic_NilData(t *testing.T) {
	// nil データでもパニックしないこと
	got := renderTemplateDynamic("Hello world", nil)
	if got != "Hello world" {
		t.Errorf("nilデータでも静的テキストは描画されるべき: got %q", got)
	}
}

// ─── wrapBase ─────────────────────────────────────────────────────────────────

func TestWrapBase_ContainsContent(t *testing.T) {
	content := "<p>Test content</p>"
	got := wrapBase(content)
	if !strings.Contains(got, content) {
		t.Errorf("wrapBase: コンテンツが含まれるべき: %q", got)
	}
}

func TestWrapBase_ContainsKizashiBranding(t *testing.T) {
	got := wrapBase("test")
	if !strings.Contains(got, "Kizashi") {
		t.Error("wrapBase: ブランド名 'Kizashi' が含まれるべき")
	}
}

func TestWrapBase_IsValidHTML(t *testing.T) {
	got := wrapBase("<p>hello</p>")
	if !strings.HasPrefix(strings.TrimSpace(got), "<!DOCTYPE html>") {
		t.Errorf("wrapBase: DOCTYPE宣言で始まるべき")
	}
}

func TestWrapBase_EmptyContent(t *testing.T) {
	// 空コンテンツでもパニックしないこと
	got := wrapBase("")
	if got == "" {
		t.Error("空コンテンツでも HTMLラッパーは返されるべき")
	}
}

// ─── NewSenderFromEnv ─────────────────────────────────────────────────────────

func TestNewSenderFromEnv_NilWhenNoSMTP(t *testing.T) {
	// SMTP_HOST が未設定の場合は nil を返す
	t.Setenv("SMTP_HOST", "")
	s := NewSenderFromEnv()
	if s != nil {
		t.Error("SMTP_HOST 未設定時は nil を返すべき")
	}
}

func TestNewSenderFromEnv_ReturnsNonNilWithHost(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "noreply@example.com")
	t.Setenv("SMTP_USERNAME", "user@example.com")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("EDR_BASE_URL", "https://edr.example.com")

	s := NewSenderFromEnv()
	if s == nil {
		t.Fatal("SMTP_HOST 設定時は nil でないべき")
	}
	if s.BaseURL() != "https://edr.example.com" {
		t.Errorf("BaseURL = %q, want https://edr.example.com", s.BaseURL())
	}
}

func TestNewSenderFromEnv_DefaultPort587(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "")
	s := NewSenderFromEnv()
	if s == nil {
		t.Fatal("non-nil expected")
	}
	if s.port != 587 {
		t.Errorf("デフォルトポートは 587 のはず: got %d", s.port)
	}
}

func TestNewSenderFromEnv_FromFallsBackToUser(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "")
	t.Setenv("SMTP_USERNAME", "user@example.com")

	s := NewSenderFromEnv()
	if s == nil {
		t.Fatal("non-nil expected")
	}
	if s.from != "user@example.com" {
		t.Errorf("from が user にフォールバックされるべき: got %q", s.from)
	}
}
