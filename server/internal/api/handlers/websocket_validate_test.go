package handlers

import (
	"os"
	"testing"
)

func TestAllowedWSOrigins_EnvUnset_ReturnsNil(t *testing.T) {
	os.Unsetenv("ALLOWED_ORIGINS")
	got := allowedWSOrigins()
	if got != nil {
		t.Errorf("allowedWSOrigins with no env = %v, want nil (allow all)", got)
	}
}

func TestAllowedWSOrigins_SingleOrigin_ContainsIt(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	got := allowedWSOrigins()
	if !got["https://app.example.com"] {
		t.Errorf("expected https://app.example.com in allowed origins, got %v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 origin, got %d: %v", len(got), got)
	}
}

func TestAllowedWSOrigins_MultipleOrigins_ContainsAll(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	got := allowedWSOrigins()
	if !got["https://app.example.com"] || !got["https://admin.example.com"] {
		t.Errorf("both origins should be present, got %v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 origins, got %d", len(got))
	}
}

func TestAllowedWSOrigins_WhitespaceTrimmed(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "  https://a.com  ,  https://b.com  ")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	got := allowedWSOrigins()
	if !got["https://a.com"] || !got["https://b.com"] {
		t.Errorf("whitespace should be trimmed, got %v", got)
	}
}

func TestAllowedWSOrigins_EmptyEntries_Skipped(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "https://app.com,,, ,")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	got := allowedWSOrigins()
	if got[""] {
		t.Error("empty string should not be in allowed origins")
	}
	if len(got) != 1 {
		t.Errorf("only 1 valid origin expected, got %d: %v", len(got), got)
	}
}

func TestAllowedWSOrigins_UnknownOrigin_NotPresent(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	got := allowedWSOrigins()
	if got["https://evil.example.com"] {
		t.Error("unlisted origin should not be present")
	}
}
