package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// validateTagName のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateTagName_ValidNames(t *testing.T) {
	// 有効なタグ名はエラーなく通過する
	valid := []string{
		"production",
		"prod-server-01",
		"web_backend",
		"v1.2.3",
		"EDR-Agent",
		"tag123",
		"a",
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			got := validateTagName(name)
			if got != "" {
				t.Errorf("validateTagName(%q) = %q, want \"\"", name, got)
			}
		})
	}
}

func TestValidateTagName_EmptyIsInvalid(t *testing.T) {
	// 空文字列はエラーを返す
	got := validateTagName("")
	if got == "" {
		t.Error("validateTagName(\"\") = \"\", エラーが期待されました")
	}
}

func TestValidateTagName_SpaceOnlyIsInvalid(t *testing.T) {
	// スペースのみのタグ名はエラーを返す
	got := validateTagName("   ")
	if got == "" {
		t.Error("validateTagName(\"   \") = \"\", エラーが期待されました")
	}
}

func TestValidateTagName_TooLong(t *testing.T) {
	// 64 文字を超えるタグ名はエラーを返す
	name := strings.Repeat("a", maxTagNameLength+1)
	got := validateTagName(name)
	if got == "" {
		t.Errorf("validateTagName(%d文字) = \"\", エラーが期待されました", len(name))
	}
}

func TestValidateTagName_ExactlyMaxLength(t *testing.T) {
	// ちょうど 64 文字のタグ名は有効
	name := strings.Repeat("a", maxTagNameLength)
	got := validateTagName(name)
	if got != "" {
		t.Errorf("validateTagName(64文字) = %q, want \"\"", got)
	}
}

func TestValidateTagName_InvalidCharacters(t *testing.T) {
	// 禁止文字（スペース、スラッシュ、@など）を含むタグ名はエラーを返す
	invalid := []string{
		"tag name", // スペース
		"tag/name", // スラッシュ
		"tag@host", // アット記号
		"tag!",     // 感嘆符
		"tag#1",    // シャープ
		"<script>", // 山括弧
		"tag;drop", // セミコロン
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			got := validateTagName(name)
			if got == "" {
				t.Errorf("validateTagName(%q): エラーが期待されましたが nil でした", name)
			}
		})
	}
}

func TestValidateTagName_LeadingTrailingSpaceTrimmed(t *testing.T) {
	// 前後のスペースはトリムされてから検証される（有効な名前はエラーなし）
	got := validateTagName("  production  ")
	if got != "" {
		t.Errorf("validateTagName(\" production \") = %q, want \"\"", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// normalizeTagName のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeTagName_LowercaseConversion(t *testing.T) {
	// 大文字を小文字に変換する
	tests := []struct {
		input string
		want  string
	}{
		{"Production", "production"},
		{"EDR-AGENT", "edr-agent"},
		{"Web_Backend", "web_backend"},
		{"V1.2.3", "v1.2.3"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeTagName(tc.input)
			if got != tc.want {
				t.Errorf("normalizeTagName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeTagName_TrimSpaces(t *testing.T) {
	// 前後の空白を除去する
	got := normalizeTagName("  prod  ")
	want := "prod"
	if got != want {
		t.Errorf("normalizeTagName(\"  prod  \") = %q, want %q", got, want)
	}
}

func TestNormalizeTagName_AlreadyNormalized(t *testing.T) {
	// すでに正規化済みの文字列はそのまま返る
	input := "production-server-01"
	got := normalizeTagName(input)
	if got != input {
		t.Errorf("normalizeTagName(%q) = %q, want %q", input, got, input)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// deduplicateTags のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestDeduplicateTags_RemovesDuplicates(t *testing.T) {
	// 重複するタグを除去する
	input := []string{"prod", "dev", "prod", "staging", "dev"}
	got := deduplicateTags(input)
	want := []string{"prod", "dev", "staging"}
	if len(got) != len(want) {
		t.Fatalf("deduplicateTags: len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("deduplicateTags[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDeduplicateTags_NoDuplicates(t *testing.T) {
	// 重複がない場合はそのまま返す
	input := []string{"alpha", "beta", "gamma"}
	got := deduplicateTags(input)
	if len(got) != 3 {
		t.Errorf("deduplicateTags(重複なし): len = %d, want 3", len(got))
	}
}

func TestDeduplicateTags_EmptySlice(t *testing.T) {
	// 空スライスは空スライスを返す
	got := deduplicateTags([]string{})
	if len(got) != 0 {
		t.Errorf("deduplicateTags([]): len = %d, want 0", len(got))
	}
}

func TestDeduplicateTags_SingleElement(t *testing.T) {
	// 単一要素のスライスはそのまま返す
	got := deduplicateTags([]string{"prod"})
	if len(got) != 1 || got[0] != "prod" {
		t.Errorf("deduplicateTags([\"prod\"]) = %v, want [\"prod\"]", got)
	}
}

func TestDeduplicateTags_PreservesOrder(t *testing.T) {
	// 最初に出現した順序を保持する
	input := []string{"c", "a", "b", "a", "c"}
	got := deduplicateTags(input)
	expected := []string{"c", "a", "b"}
	if len(got) != len(expected) {
		t.Fatalf("deduplicateTags: len = %d, want %d", len(got), len(expected))
	}
	for i, v := range expected {
		if got[i] != v {
			t.Errorf("deduplicateTags[%d] = %q, want %q", i, got[i], v)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// containsTag のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestContainsTag_Found(t *testing.T) {
	// タグリストに対象タグが含まれる場合 true を返す
	tags := []string{"prod", "web", "backend"}
	if !containsTag(tags, "web") {
		t.Error("containsTag([...], \"web\") = false, want true")
	}
}

func TestContainsTag_NotFound(t *testing.T) {
	// タグリストに対象タグが含まれない場合 false を返す
	tags := []string{"prod", "web", "backend"}
	if containsTag(tags, "frontend") {
		t.Error("containsTag([...], \"frontend\") = true, want false")
	}
}

func TestContainsTag_EmptyList(t *testing.T) {
	// 空リストでは常に false を返す
	if containsTag([]string{}, "prod") {
		t.Error("containsTag([], \"prod\") = true, want false")
	}
}

func TestContainsTag_CaseSensitive(t *testing.T) {
	// 大文字小文字を区別する（"Prod" != "prod"）
	tags := []string{"prod"}
	if containsTag(tags, "Prod") {
		t.Error("containsTag: 大文字小文字を区別しないマッチが発生しました")
	}
}

// `internal/store` の検査ファイルに `deduplicateTags` と `containsTag` の
// 写しが置いてありました。**本物はこのパッケージにあり、上の5本が
// すでに試しています** —— 写しの方を消しました。
//
// （最初「本物には検査が無い」と書いて表を1つ足しました。上の5本を
// 見落としていました。重複を消して、無かった分だけ残します。）

// 正規化は、重複除去の前に効いていること。
//
// **`Prod` と `prod` は同じタグです。** 正規化せずに重複を除くと、
// 大文字違いのタグが2つ残り、絞り込みが片方にしか当たりません。
func TestNormalizeThenDeduplicate(t *testing.T) {
	in := []string{"Prod", "prod", " PROD "}
	norm := make([]string, 0, len(in))
	for _, t0 := range in {
		norm = append(norm, normalizeTagName(t0))
	}
	got := deduplicateTags(norm)
	if len(got) != 1 || got[0] != "prod" {
		t.Errorf("正規化してから重複除去 = %v, want [prod]", got)
	}
}
