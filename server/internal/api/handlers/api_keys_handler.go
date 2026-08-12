package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// APIKeyHandler provides endpoints to manage programmatic API keys.
type APIKeyHandler struct {
	store *store.APIKeyStore
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(s *store.APIKeyStore) *APIKeyHandler {
	return &APIKeyHandler{store: s}
}

// createAPIKeyRequest is the JSON body for POST /api/v1/api-keys.
type createAPIKeyRequest struct {
	Name      string   `json:"name"       binding:"required"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"` // RFC3339 or empty
}

var validAPIKeyScopes = map[string]struct{}{"read": {}, "write": {}, "admin": {}}

// validateAPIKeyScopes returns the first invalid scope found, or "".
func validateAPIKeyScopes(scopes []string) string {
	for _, s := range scopes {
		if _, ok := validAPIKeyScopes[s]; !ok {
			return s
		}
	}
	return ""
}

// normalizeAPIKeyScopes returns ["read"] when scopes is empty.
func normalizeAPIKeyScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"read"}
	}
	return scopes
}

// List returns all API keys for the authenticated user.
// GET /api/v1/api-keys
func (h *APIKeyHandler) List(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	keys, err := h.store.ListByUser(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "APIキー一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": keys})
}

// Create generates a new API key and returns the raw key once.
// POST /api/v1/api-keys
func (h *APIKeyHandler) Create(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var req createAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name は必須です"})
		return
	}

	// Validate scopes
	if bad := validateAPIKeyScopes(req.Scopes); bad != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "スコープは read/write/admin のいずれかを指定してください"})
		return
	}
	req.Scopes = normalizeAPIKeyScopes(req.Scopes)

	// Parse optional expiry
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at は RFC3339 形式で指定してください"})
			return
		}
		expiresAt = &t
	}

	rawKey, err := h.store.Create(c.Request.Context(), uid, req.Name, req.Scopes, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "APIキーの作成に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"key":     rawKey,
		"message": "このキーは一度しか表示されません。安全な場所に保存してください。",
	})
}

// Revoke marks an API key as revoked.
// DELETE /api/v1/api-keys/:id
func (h *APIKeyHandler) Revoke(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	if err := h.store.Revoke(c.Request.Context(), id, uid); err != nil {
		if strings.Contains(err.Error(), "見つからない") || strings.Contains(err.Error(), "アクセス権") {
			c.JSON(http.StatusNotFound, gin.H{"error": "APIキーが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "APIキーの失効に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "APIキーを失効しました"})
}
