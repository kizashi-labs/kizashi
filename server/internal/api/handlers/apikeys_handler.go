package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/apikeys"
	"github.com/gin-gonic/gin"
)

// APIKeysHandler provides API key management endpoints backed by the apikeys.Manager.
// This handler is separate from the existing APIKeyHandler (which uses store.APIKeyStore).
// It provides enhanced endpoints at /api/v1/apikeys and /api/v1/admin/apikeys.
type APIKeysHandler struct {
	mgr *apikeys.Manager
}

// NewAPIKeysHandler creates a new APIKeysHandler.
func NewAPIKeysHandler(mgr *apikeys.Manager) *APIKeysHandler {
	return &APIKeysHandler{mgr: mgr}
}

// ListKeys returns all API keys for the authenticated user.
// GET /api/v1/apikeys
func (h *APIKeysHandler) ListKeys(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	keys, err := h.mgr.List(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list api keys"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": keys, "total": len(keys)})
}

// CreateKey generates a new API key and returns the raw key once.
// POST /api/v1/apikeys
func (h *APIKeysHandler) CreateKey(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	userRole, _ := c.Get("user_role")
	role, _ := userRole.(string)

	var req struct {
		Name          string   `json:"name" binding:"required"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays *int     `json:"expires_in_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	// Validate scopes
	validScopes := make(map[string]bool)
	for _, s := range apikeys.ValidScopes {
		validScopes[s] = true
	}
	for _, s := range req.Scopes {
		if !validScopes[s] {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":        "invalid scope: " + s,
				"valid_scopes": apikeys.ValidScopes,
			})
			return
		}
	}

	var expiresIn *time.Duration
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		d := time.Duration(*req.ExpiresInDays) * 24 * time.Hour
		expiresIn = &d
	}

	if role == "" {
		role = "analyst"
	}

	key, rawKey, err := h.mgr.Generate(c.Request.Context(), req.Name, uid, role, req.Scopes, expiresIn)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create api key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"key":     rawKey,
		"api_key": key,
		"message": "This key is shown only once. Store it securely.",
	})
}

// RevokeKey disables an API key owned by the authenticated user.
// DELETE /api/v1/apikeys/:id
func (h *APIKeysHandler) RevokeKey(c *gin.Context) {
	id := c.Param("id")
	if err := h.mgr.Revoke(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found or already revoked"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "api key revoked", "id": id})
}

// AdminListAllKeys returns all API keys across all users (admin only).
// GET /api/v1/admin/apikeys
func (h *APIKeysHandler) AdminListAllKeys(c *gin.Context) {
	keys, err := h.mgr.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list api keys"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": keys, "total": len(keys)})
}
