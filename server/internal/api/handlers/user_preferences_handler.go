package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// validPreferenceThemes は許可された UI テーマの集合です。
var validPreferenceThemes = map[string]struct{}{
	"dark":          {},
	"light":         {},
	"system":        {},
	"high-contrast": {},
}

// validPreferenceLanguages は許可された言語コードの集合です。
var validPreferenceLanguages = map[string]struct{}{
	"ja": {},
	"en": {},
	"zh": {},
	"ko": {},
	"fr": {},
	"de": {},
	"es": {},
}

// applyPreferenceDefaults はユーザー設定に未設定フィールドのデフォルト値を補完します。
// 呼び出し元が DB に保存する前に必ず適用してください。
func applyPreferenceDefaults(p *store.UserPreferences) {
	if p.Theme == "" {
		p.Theme = "dark"
	}
	if p.Language == "" {
		p.Language = "ja"
	}
	if p.Timezone == "" {
		p.Timezone = "Asia/Tokyo"
	}
	if p.ItemsPerPage <= 0 {
		p.ItemsPerPage = 20
	}
}

// validatePreferenceTheme はテーマ設定を検証します。
func validatePreferenceTheme(theme string) string {
	if theme == "" {
		return ""
	}
	if _, ok := validPreferenceThemes[theme]; !ok {
		return "theme は dark/light/system/high-contrast のいずれかを指定してください"
	}
	return ""
}

// validatePreferenceLanguage は言語設定を検証します。
func validatePreferenceLanguage(language string) string {
	if language == "" {
		return ""
	}
	if _, ok := validPreferenceLanguages[language]; !ok {
		return "language は ja/en/zh/ko/fr/de/es のいずれかを指定してください"
	}
	return ""
}

// validateItemsPerPage は1ページあたりの表示件数を検証します。
// 有効範囲は 1〜200 です。0 以下はデフォルト 20 に補完されます。
func validateItemsPerPage(n int) string {
	if n <= 0 {
		return ""
	}
	if n > 200 {
		return "items_per_page は 1〜200 の範囲で指定してください"
	}
	return ""
}

type UserPreferencesHandler struct {
	store *store.UserPreferencesStore
}

func NewUserPreferencesHandler(s *store.UserPreferencesStore) *UserPreferencesHandler {
	return &UserPreferencesHandler{store: s}
}

// Get handles GET /api/v1/user/preferences
func (h *UserPreferencesHandler) Get(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	prefs, err := h.store.Get(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, prefs)
}

// Update handles PUT /api/v1/user/preferences
func (h *UserPreferencesHandler) Update(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	var req store.UserPreferences
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	prefs, err := h.store.Upsert(c.Request.Context(), userID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定の保存に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, prefs)
}
