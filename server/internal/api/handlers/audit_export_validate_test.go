package handlers

import (
	"testing"
)

func TestEscapeCEF_PlainString_Unchanged(t *testing.T) {
	if got := escapeCEF("hello world"); got != "hello world" {
		t.Errorf("escapeCEF(\"hello world\") = %q, want unchanged", got)
	}
}

func TestEscapeCEF_Backslash_Escaped(t *testing.T) {
	// Each backslash is doubled: "C:\Windows" → "C:\\Windows"
	got := escapeCEF(`C:\Windows\System32`)
	want := `C:\\Windows\\System32`
	if got != want {
		t.Errorf("escapeCEF backslash: got %q, want %q", got, want)
	}
}

func TestEscapeCEF_Pipe_Escaped(t *testing.T) {
	got := escapeCEF("field|value")
	want := `field\|value`
	if got != want {
		t.Errorf("escapeCEF pipe: got %q, want %q", got, want)
	}
}

func TestEscapeCEF_BackslashAndPipe_BothEscaped(t *testing.T) {
	// Input: a\|b  (backslash then pipe)
	// Step1: a\\|b (backslash doubled)
	// Step2: a\\\|b (pipe escaped — backslash then escaped-pipe)
	got := escapeCEF(`a\|b`)
	want := `a\\\|b`
	if got != want {
		t.Errorf("escapeCEF backslash+pipe: got %q, want %q", got, want)
	}
}

func TestEscapeCEF_EmptyString_ReturnsEmpty(t *testing.T) {
	if got := escapeCEF(""); got != "" {
		t.Errorf("escapeCEF(\"\") = %q, want \"\"", got)
	}
}

func TestEscapeCEF_NoPipeNoBackslash_PassThrough(t *testing.T) {
	s := "process: notepad.exe pid=1234"
	if got := escapeCEF(s); got != s {
		t.Errorf("escapeCEF with no special chars changed: %q", got)
	}
}
