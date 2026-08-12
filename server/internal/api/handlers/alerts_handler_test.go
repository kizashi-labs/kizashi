package handlers

import (
	"testing"
	"time"
)

// ─── csvField tests ──────────────────────────────────────────────────────────

func TestCSVField_PlainString(t *testing.T) {
	if got := csvField("hello"); got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestCSVField_ContainsComma(t *testing.T) {
	got := csvField("hello,world")
	want := `"hello,world"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCSVField_ContainsQuote(t *testing.T) {
	got := csvField(`say "hi"`)
	want := `"say ""hi"""`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCSVField_ContainsNewline(t *testing.T) {
	got := csvField("line1\nline2")
	want := "\"line1\nline2\""
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCSVField_ContainsCR(t *testing.T) {
	got := csvField("col\rval")
	if len(got) < 2 || got[0] != '"' {
		t.Fatalf("CRを含む場合はクォートされるべきです、got %q", got)
	}
}

func TestCSVField_EmptyString(t *testing.T) {
	if got := csvField(""); got != "" {
		t.Fatalf("空文字列: got %q, want %q", got, "")
	}
}

// ─── parseTimeParam tests ────────────────────────────────────────────────────

func TestParseTimeParam_EmptyReturnsNil(t *testing.T) {
	if got := parseTimeParam(""); got != nil {
		t.Fatalf("空文字列はnilを返すべきです、got %v", got)
	}
}

func TestParseTimeParam_ValidRFC3339(t *testing.T) {
	input := "2026-03-17T10:00:00Z"
	got := parseTimeParam(input)
	if got == nil {
		t.Fatal("有効な時刻はnilでないはずです")
	}
	want := time.Date(2026, 3, 17, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTimeParam_InvalidReturnsNil(t *testing.T) {
	if got := parseTimeParam("not-a-date"); got != nil {
		t.Fatalf("無効な日時はnilを返すべきです、got %v", got)
	}
}

func TestParseTimeParam_WithOffset(t *testing.T) {
	input := "2026-03-17T19:00:00+09:00"
	got := parseTimeParam(input)
	if got == nil {
		t.Fatal("タイムゾーンオフセット付きはnilでないはずです")
	}
	// JST +09:00 → UTC 10:00
	wantUTC := time.Date(2026, 3, 17, 10, 0, 0, 0, time.UTC)
	if !got.UTC().Equal(wantUTC) {
		t.Fatalf("UTC変換: got %v, want %v", got.UTC(), wantUTC)
	}
}
