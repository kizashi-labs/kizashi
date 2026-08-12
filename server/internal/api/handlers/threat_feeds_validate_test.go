package handlers

import (
	"strings"
	"testing"
)

// ─── parseTxtFeed ────────────────────────────────────────────────────────────

func TestParseTxtFeed_BasicValues(t *testing.T) {
	body := "192.0.2.1\n10.0.0.1\n"
	got := parseTxtFeed(body)
	if len(got) != 2 {
		t.Fatalf("parseTxtFeed: want 2 entries, got %d: %v", len(got), got)
	}
}

func TestParseTxtFeed_SkipsComments(t *testing.T) {
	body := "# comment\n192.0.2.1\n; another comment\n"
	got := parseTxtFeed(body)
	if len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("parseTxtFeed: want [192.0.2.1], got %v", got)
	}
}

func TestParseTxtFeed_SkipsBlankLines(t *testing.T) {
	body := "\n\n192.0.2.1\n\n"
	got := parseTxtFeed(body)
	if len(got) != 1 {
		t.Errorf("parseTxtFeed: want 1 entry, got %d", len(got))
	}
}

func TestParseTxtFeed_InlineComment_StripsSuffix(t *testing.T) {
	body := "192.0.2.1 # this is a bad IP\n"
	got := parseTxtFeed(body)
	if len(got) != 1 {
		t.Fatalf("parseTxtFeed inline comment: want 1, got %d", len(got))
	}
	if strings.Contains(got[0], "#") {
		t.Errorf("parseTxtFeed: inline comment should be stripped, got %q", got[0])
	}
}

func TestParseTxtFeed_Empty(t *testing.T) {
	got := parseTxtFeed("")
	if len(got) != 0 {
		t.Errorf("parseTxtFeed(empty) = %v, want empty slice", got)
	}
}

// ─── parseCSVFeed ────────────────────────────────────────────────────────────

func TestParseCSVFeed_BasicValues(t *testing.T) {
	body := "192.0.2.1,description\n10.0.0.1,another\n"
	got := parseCSVFeed(body)
	if len(got) != 2 {
		t.Fatalf("parseCSVFeed: want 2 entries, got %d: %v", len(got), got)
	}
	if got[0] != "192.0.2.1" {
		t.Errorf("parseCSVFeed: first = %q, want '192.0.2.1'", got[0])
	}
}

func TestParseCSVFeed_SkipsComments(t *testing.T) {
	body := "# header\n192.0.2.1,info\n"
	got := parseCSVFeed(body)
	if len(got) != 1 {
		t.Errorf("parseCSVFeed: want 1, got %d", len(got))
	}
}

func TestParseCSVFeed_QuotedValues(t *testing.T) {
	body := "\"192.0.2.1\",description\n"
	got := parseCSVFeed(body)
	if len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("parseCSVFeed quoted: want [192.0.2.1], got %v", got)
	}
}

func TestParseCSVFeed_Empty(t *testing.T) {
	got := parseCSVFeed("")
	if len(got) != 0 {
		t.Errorf("parseCSVFeed(empty) = %v, want empty slice", got)
	}
}

func TestParseCSVFeed_SingleColumn(t *testing.T) {
	body := "192.0.2.1\n192.0.2.2\n"
	got := parseCSVFeed(body)
	if len(got) != 2 {
		t.Errorf("parseCSVFeed single col: want 2, got %d", len(got))
	}
}
