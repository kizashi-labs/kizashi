package email

import "testing"

// Exercises the pure template renderers (no SMTP / network).
func TestRenderTemplates(t *testing.T) {
	out, err := renderTemplate("Hello {{.name}}, code {{.code}}", map[string]string{"name": "Cov", "code": "123"})
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}
	if out == "" {
		t.Fatalf("renderTemplate returned empty")
	}
	// 壊れたテンプレートは落ちませんが、黙って空を返すのもやめました。
	if _, err := renderTemplate("{{.unclosed", map[string]string{}); err == nil {
		t.Error("壊れたテンプレートがエラーになっていません")
	}

	dyn, err := renderTemplateDynamic("Items: {{range .Items}}{{.}} {{end}}",
		struct{ Items []string }{Items: []string{"a", "b"}})
	if err != nil {
		t.Fatalf("renderTemplateDynamic: %v", err)
	}
	if dyn == "" {
		t.Fatalf("renderTemplateDynamic returned empty")
	}
}
