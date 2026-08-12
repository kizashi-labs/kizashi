package handlers

import "testing"

// ─── generateSlug ─────────────────────────────────────────────────────────────

func TestGenerateSlug_BasicTitle(t *testing.T) {
	got := generateSlug("Hello World")
	want := "hello-world"
	if got != want {
		t.Errorf("generateSlug(%q) = %q, want %q", "Hello World", got, want)
	}
}

func TestGenerateSlug_RemovesSpecialChars(t *testing.T) {
	got := generateSlug("Hello, World!")
	want := "hello-world"
	if got != want {
		t.Errorf("generateSlug(%q) = %q, want %q", "Hello, World!", got, want)
	}
}

func TestGenerateSlug_CollapseMultipleHyphens(t *testing.T) {
	got := generateSlug("foo  bar  baz")
	// multiple spaces → multiple hyphens → collapsed
	if got != "foo-bar-baz" {
		t.Errorf("generateSlug(複数スペース) = %q, want foo-bar-baz", got)
	}
}

func TestGenerateSlug_TrimsLeadingTrailingHyphens(t *testing.T) {
	got := generateSlug("  hello  ")
	if got != "hello" {
		t.Errorf("generateSlug(前後スペース) = %q, want hello", got)
	}
}

func TestGenerateSlug_EmptyString(t *testing.T) {
	got := generateSlug("")
	if got != "" {
		t.Errorf("generateSlug(%q) = %q, want empty", "", got)
	}
}

func TestGenerateSlug_AlphanumericPreserved(t *testing.T) {
	got := generateSlug("abc123")
	if got != "abc123" {
		t.Errorf("generateSlug(%q) = %q, want abc123", "abc123", got)
	}
}

func TestGenerateSlug_JapaneseCharsRemoved(t *testing.T) {
	// Japanese chars are non-[a-z0-9-] so they are stripped
	got := generateSlug("hello世界")
	if got != "hello" {
		t.Errorf("generateSlug(日本語混在) = %q, want hello", got)
	}
}

func TestGenerateSlug_AllUpperCase(t *testing.T) {
	got := generateSlug("ALERT MANAGEMENT")
	want := "alert-management"
	if got != want {
		t.Errorf("generateSlug(%q) = %q, want %q", "ALERT MANAGEMENT", got, want)
	}
}

func TestGenerateSlug_NumbersAndHyphens(t *testing.T) {
	got := generateSlug("EDR Platform v1.0")
	// '.' is stripped → "edr-platform-v10"
	if got != "edr-platform-v10" {
		t.Errorf("generateSlug(バージョン番号) = %q, want edr-platform-v10", got)
	}
}

func TestGenerateSlug_OnlySpecialChars(t *testing.T) {
	got := generateSlug("!!!")
	if got != "" {
		t.Errorf("generateSlug(特殊文字のみ) = %q, want empty", got)
	}
}
