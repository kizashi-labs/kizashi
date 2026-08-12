package email

import "testing"

// Exercises the pure template renderers (no SMTP / network).
func TestRenderTemplates(t *testing.T) {
	out := renderTemplate("Hello {{.name}}, code {{.code}}", map[string]string{"name": "Cov", "code": "123"})
	if out == "" {
		t.Fatalf("renderTemplate returned empty")
	}
	// Invalid template falls back gracefully rather than panicking.
	_ = renderTemplate("{{.unclosed", map[string]string{})

	dyn := renderTemplateDynamic("Items: {{range .Items}}{{.}} {{end}}",
		struct{ Items []string }{Items: []string{"a", "b"}})
	if dyn == "" {
		t.Fatalf("renderTemplateDynamic returned empty")
	}
}
