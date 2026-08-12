package handlers

import (
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// applyPreferenceDefaults のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyPreferenceDefaults_AllEmpty(t *testing.T) {
	// すべてのフィールドが空のとき、デフォルト値が補完される
	p := &store.UserPreferences{}
	applyPreferenceDefaults(p)

	if p.Theme != "dark" {
		t.Errorf("デフォルトテーマ = %q, want \"dark\"", p.Theme)
	}
	if p.Language != "ja" {
		t.Errorf("デフォルト言語 = %q, want \"ja\"", p.Language)
	}
	if p.Timezone != "Asia/Tokyo" {
		t.Errorf("デフォルトタイムゾーン = %q, want \"Asia/Tokyo\"", p.Timezone)
	}
	if p.ItemsPerPage != 20 {
		t.Errorf("デフォルト ItemsPerPage = %d, want 20", p.ItemsPerPage)
	}
}

func TestApplyPreferenceDefaults_ExistingValuesPreserved(t *testing.T) {
	// 既存のフィールドは上書きされない
	p := &store.UserPreferences{
		Theme:        "light",
		Language:     "en",
		Timezone:     "America/New_York",
		ItemsPerPage: 50,
	}
	applyPreferenceDefaults(p)

	if p.Theme != "light" {
		t.Errorf("テーマが上書きされました: %q", p.Theme)
	}
	if p.Language != "en" {
		t.Errorf("言語が上書きされました: %q", p.Language)
	}
	if p.Timezone != "America/New_York" {
		t.Errorf("タイムゾーンが上書きされました: %q", p.Timezone)
	}
	if p.ItemsPerPage != 50 {
		t.Errorf("ItemsPerPage が上書きされました: %d", p.ItemsPerPage)
	}
}

func TestApplyPreferenceDefaults_ZeroItemsPerPageDefaultsTo20(t *testing.T) {
	// ItemsPerPage が 0 以下の場合はデフォルト 20 に補完される
	for _, n := range []int{0, -1, -100} {
		p := &store.UserPreferences{
			Theme:        "dark",
			Language:     "ja",
			Timezone:     "Asia/Tokyo",
			ItemsPerPage: n,
		}
		applyPreferenceDefaults(p)
		if p.ItemsPerPage != 20 {
			t.Errorf("ItemsPerPage(%d) のデフォルト = %d, want 20", n, p.ItemsPerPage)
		}
	}
}

func TestApplyPreferenceDefaults_PartialEmpty(t *testing.T) {
	// 一部のフィールドのみ空の場合、空のフィールドのみデフォルトが補完される
	p := &store.UserPreferences{
		Theme:    "light",
		Language: "", // 空 → デフォルト補完
		Timezone: "Europe/London",
	}
	applyPreferenceDefaults(p)

	if p.Theme != "light" {
		t.Errorf("テーマが変更されました: %q", p.Theme)
	}
	if p.Language != "ja" {
		t.Errorf("空言語のデフォルト = %q, want \"ja\"", p.Language)
	}
	if p.Timezone != "Europe/London" {
		t.Errorf("タイムゾーンが変更されました: %q", p.Timezone)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validatePreferenceTheme のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidatePreferenceTheme_Valid(t *testing.T) {
	// 有効なテーマ値はエラーなく通過する
	for theme := range validPreferenceThemes {
		t.Run(theme, func(t *testing.T) {
			got := validatePreferenceTheme(theme)
			if got != "" {
				t.Errorf("validatePreferenceTheme(%q) = %q, want \"\"", theme, got)
			}
		})
	}
}

func TestValidatePreferenceTheme_EmptyIsValid(t *testing.T) {
	// 空文字列は検証をスキップして "" を返す（デフォルト補完は別関数担当）
	got := validatePreferenceTheme("")
	if got != "" {
		t.Errorf("validatePreferenceTheme(\"\") = %q, want \"\"", got)
	}
}

func TestValidatePreferenceTheme_Invalid(t *testing.T) {
	// 無効なテーマ値はエラーを返す
	invalid := []string{"blue", "red", "auto", "custom", "neon"}
	for _, theme := range invalid {
		t.Run(theme, func(t *testing.T) {
			got := validatePreferenceTheme(theme)
			if got == "" {
				t.Errorf("validatePreferenceTheme(%q): エラーが期待されましたが nil でした", theme)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validatePreferenceLanguage のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidatePreferenceLanguage_Valid(t *testing.T) {
	// 有効な言語コードはエラーなく通過する
	for lang := range validPreferenceLanguages {
		t.Run(lang, func(t *testing.T) {
			got := validatePreferenceLanguage(lang)
			if got != "" {
				t.Errorf("validatePreferenceLanguage(%q) = %q, want \"\"", lang, got)
			}
		})
	}
}

func TestValidatePreferenceLanguage_EmptyIsValid(t *testing.T) {
	// 空文字列は検証をスキップして "" を返す
	got := validatePreferenceLanguage("")
	if got != "" {
		t.Errorf("validatePreferenceLanguage(\"\") = %q, want \"\"", got)
	}
}

func TestValidatePreferenceLanguage_Invalid(t *testing.T) {
	// 未知の言語コードはエラーを返す
	invalid := []string{"zh-TW", "pt", "ru", "ar", "xyz"}
	for _, lang := range invalid {
		t.Run(lang, func(t *testing.T) {
			got := validatePreferenceLanguage(lang)
			if got == "" {
				t.Errorf("validatePreferenceLanguage(%q): エラーが期待されましたが nil でした", lang)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateItemsPerPage のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateItemsPerPage_ValidRange(t *testing.T) {
	// 1〜200 の範囲はエラーなし
	valid := []int{1, 10, 20, 50, 100, 200}
	for _, n := range valid {
		got := validateItemsPerPage(n)
		if got != "" {
			t.Errorf("validateItemsPerPage(%d) = %q, want \"\"", n, got)
		}
	}
}

func TestValidateItemsPerPage_ZeroOrNegativeIsValid(t *testing.T) {
	// 0 以下は検証をスキップ（デフォルト補完は applyPreferenceDefaults が担当）
	for _, n := range []int{0, -1, -50} {
		got := validateItemsPerPage(n)
		if got != "" {
			t.Errorf("validateItemsPerPage(%d) = %q, want \"\"", n, got)
		}
	}
}

func TestValidateItemsPerPage_TooLarge(t *testing.T) {
	// 200 を超える値はエラーを返す
	invalid := []int{201, 500, 1000, 9999}
	for _, n := range invalid {
		got := validateItemsPerPage(n)
		if got == "" {
			t.Errorf("validateItemsPerPage(%d): エラーが期待されましたが nil でした", n)
		}
	}
}

func TestValidateItemsPerPage_ExactlyMaxIsValid(t *testing.T) {
	// ちょうど 200 は有効
	got := validateItemsPerPage(200)
	if got != "" {
		t.Errorf("validateItemsPerPage(200) = %q, want \"\"", got)
	}
}

func TestValidateItemsPerPage_ExactlyOneIsValid(t *testing.T) {
	// ちょうど 1 は有効
	got := validateItemsPerPage(1)
	if got != "" {
		t.Errorf("validateItemsPerPage(1) = %q, want \"\"", got)
	}
}
