package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ─── hashKey ─────────────────────────────────────────────────────────────────

func TestHashKey_Deterministic(t *testing.T) {
	// 同じキーは常に同じハッシュを返す
	h1 := hashKey("my-api-key-12345")
	h2 := hashKey("my-api-key-12345")
	if h1 != h2 {
		t.Errorf("同じ入力で異なるハッシュ: %q vs %q", h1, h2)
	}
}

func TestHashKey_IsSHA256Hex(t *testing.T) {
	h := hashKey("test-key")
	// SHA-256 は 64 文字のhex文字列
	if len(h) != 64 {
		t.Errorf("ハッシュ長 = %d, want 64", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("ハッシュに不正な文字: %q", string(c))
		}
	}
}

func TestHashKey_MatchesManualSHA256(t *testing.T) {
	key := "verify-this-key"
	got := hashKey(key)
	sum := sha256.Sum256([]byte(key))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("hashKey(%q) = %q, want %q", key, got, want)
	}
}

func TestHashKey_EmptyString(t *testing.T) {
	h := hashKey("")
	// 空文字列のSHA-256も有効な64文字ハッシュ
	if len(h) != 64 {
		t.Errorf("空文字列のハッシュ長 = %d, want 64", len(h))
	}
}

func TestHashKey_DifferentInputsDifferentHash(t *testing.T) {
	h1 := hashKey("key-a")
	h2 := hashKey("key-b")
	if h1 == h2 {
		t.Error("異なる入力は異なるハッシュを生成するべき")
	}
}

// ─── nullStr ─────────────────────────────────────────────────────────────────

func TestNullStr_EmptyStringReturnsNil(t *testing.T) {
	if got := nullStr(""); got != nil {
		t.Errorf("空文字列は nil を返すべき: got %v", *got)
	}
}

func TestNullStr_NonEmptyReturnsPointer(t *testing.T) {
	s := "hello"
	got := nullStr(s)
	if got == nil {
		t.Fatal("非空文字列は nil でないポインタを返すべき")
	}
	if *got != s {
		t.Errorf("*got = %q, want %q", *got, s)
	}
}

func TestNullStr_WhitespaceIsNonEmpty(t *testing.T) {
	// スペースは空文字列ではないのでポインタを返す
	got := nullStr("  ")
	if got == nil {
		t.Error("スペースは nil でないポインタを返すべき")
	}
}

// ─── nilIfEmpty ──────────────────────────────────────────────────────────────

func TestNilIfEmpty_NilPointerReturnsNil(t *testing.T) {
	if got := nilIfEmpty(nil); got != nil {
		t.Errorf("nil ポインタは nil を返すべき: got %v", got)
	}
}

func TestNilIfEmpty_EmptyStringPointerReturnsNil(t *testing.T) {
	s := ""
	if got := nilIfEmpty(&s); got != nil {
		t.Errorf("空文字列ポインタは nil を返すべき: got %v", got)
	}
}

func TestNilIfEmpty_NonEmptyStringPointerReturnsValue(t *testing.T) {
	s := "value"
	got := nilIfEmpty(&s)
	if got == nil {
		t.Fatal("非空文字列は nil でないべき")
	}
	if got.(string) != "value" {
		t.Errorf("got = %v, want %q", got, "value")
	}
}

// ─── nilIfEmptyPtr ───────────────────────────────────────────────────────────

func TestNilIfEmptyPtr_NilPointerReturnsNil(t *testing.T) {
	if got := nilIfEmptyPtr(nil); got != nil {
		t.Errorf("nil ポインタは nil を返すべき: got %v", got)
	}
}

func TestNilIfEmptyPtr_EmptyStringPointerReturnsNil(t *testing.T) {
	s := ""
	if got := nilIfEmptyPtr(&s); got != nil {
		t.Errorf("空文字列ポインタは nil を返すべき: got %v", got)
	}
}

func TestNilIfEmptyPtr_NonEmptyStringPointerReturnsValue(t *testing.T) {
	s := "pattern"
	got := nilIfEmptyPtr(&s)
	if got == nil {
		t.Fatal("非空文字列は nil でないべき")
	}
	if got.(string) != "pattern" {
		t.Errorf("got = %v, want %q", got, "pattern")
	}
}

// ─── containsStr ─────────────────────────────────────────────────────────────

func TestContainsStr_Found(t *testing.T) {
	if !containsStr("Hello World", "world") {
		t.Error("'Hello World' は 'world' を含むべき (大文字小文字無視)")
	}
}

func TestContainsStr_NotFound(t *testing.T) {
	if containsStr("Hello", "xyz") {
		t.Error("'Hello' は 'xyz' を含まないべき")
	}
}

func TestContainsStr_EmptySubstring(t *testing.T) {
	// 空文字列はすべての文字列に含まれる
	if !containsStr("anything", "") {
		t.Error("空のサブ文字列は常に含まれるべき")
	}
}

func TestContainsStr_SubLongerThanString(t *testing.T) {
	if containsStr("ab", "abcdef") {
		t.Error("サブ文字列が文字列より長い場合は false を返すべき")
	}
}

func TestContainsStr_CaseInsensitive(t *testing.T) {
	cases := []struct {
		s, sub string
	}{
		{"MALWARE", "malware"},
		{"malware", "MALWARE"},
		{"MaLwArE", "malware"},
	}
	for _, tc := range cases {
		if !containsStr(tc.s, tc.sub) {
			t.Errorf("containsStr(%q, %q) = false, want true (大文字小文字無視)", tc.s, tc.sub)
		}
	}
}

// ─── toLower ─────────────────────────────────────────────────────────────────

func TestToLower_AlreadyLower(t *testing.T) {
	if got := toLower("hello"); got != "hello" {
		t.Errorf("toLower(\"hello\") = %q", got)
	}
}

func TestToLower_AllUpper(t *testing.T) {
	if got := toLower("HELLO"); got != "hello" {
		t.Errorf("toLower(\"HELLO\") = %q, want \"hello\"", got)
	}
}

func TestToLower_MixedCase(t *testing.T) {
	if got := toLower("HeLLo"); got != "hello" {
		t.Errorf("toLower(\"HeLLo\") = %q, want \"hello\"", got)
	}
}

func TestToLower_NonAlpha(t *testing.T) {
	input := "Test123!@#"
	got := toLower(input)
	if !strings.HasPrefix(got, "test") {
		t.Errorf("toLower(%q): アルファベット部分が小文字になるべき: got %q", input, got)
	}
}

func TestToLower_EmptyString(t *testing.T) {
	if got := toLower(""); got != "" {
		t.Errorf("toLower(\"\") = %q, want \"\"", got)
	}
}
