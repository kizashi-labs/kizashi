package handlers

import (
	"testing"
	"time"
)

// ─── parseTimeParam ────────────────────────────────────────────────────────

func TestParseTimeParam_ValidRFC3339_ReturnsTime(t *testing.T) {
	s := "2026-03-24T00:00:00Z"
	got := parseTimeParam(s)
	if got == nil {
		t.Fatalf("parseTimeParam(%q) = nil, want non-nil", s)
	}
	want, _ := time.Parse(time.RFC3339, s)
	if !got.Equal(want) {
		t.Errorf("parseTimeParam(%q) = %v, want %v", s, got, want)
	}
}

func TestParseTimeParam_EmptyString_ReturnsNil(t *testing.T) {
	if got := parseTimeParam(""); got != nil {
		t.Errorf("parseTimeParam(\"\") = %v, want nil", got)
	}
}

func TestParseTimeParam_InvalidFormat_ReturnsNil(t *testing.T) {
	for _, bad := range []string{"2026-03-24", "not-a-date", "01/01/2026"} {
		if got := parseTimeParam(bad); got != nil {
			t.Errorf("parseTimeParam(%q) = %v, want nil", bad, got)
		}
	}
}

// ─── csvField ──────────────────────────────────────────────────────────────

func TestCSVField_PlainString_Unchanged(t *testing.T) {
	if got := csvField("hello"); got != "hello" {
		t.Errorf("csvField(\"hello\") = %q, want \"hello\"", got)
	}
}

func TestCSVField_ContainsComma_Quoted(t *testing.T) {
	got := csvField("a,b")
	if got != `"a,b"` {
		t.Errorf("csvField(\"a,b\") = %q, want %q", got, `"a,b"`)
	}
}

func TestCSVField_ContainsDoubleQuote_Escaped(t *testing.T) {
	// Input: he said "hi"  → Output: "he said ""hi"""
	got := csvField(`he said "hi"`)
	want := `"he said ""hi"""`
	if got != want {
		t.Errorf("csvField = %q, want %q", got, want)
	}
}

func TestCSVField_ContainsNewline_Quoted(t *testing.T) {
	got := csvField("line1\nline2")
	if got != "\"line1\nline2\"" {
		t.Errorf("csvField with newline not quoted correctly: %q", got)
	}
}

func TestCSVField_EmptyString_Unchanged(t *testing.T) {
	if got := csvField(""); got != "" {
		t.Errorf("csvField(\"\") = %q, want \"\"", got)
	}
}
