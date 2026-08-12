package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// NotificationPrefsHandler manages per-user email notification preferences.
type NotificationPrefsHandler struct {
	store *store.NotificationPrefStore
}

// NewNotificationPrefsHandler creates a NotificationPrefsHandler.
func NewNotificationPrefsHandler(s *store.NotificationPrefStore) *NotificationPrefsHandler {
	return &NotificationPrefsHandler{store: s}
}

// GetPreferences returns the current user's notification preferences.
// GET /api/v1/notifications/preferences
func (h *NotificationPrefsHandler) GetPreferences(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	prefs, err := h.store.GetByUserID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, prefs)
}

// UpsertPreferences creates or updates the current user's notification preferences.
// PUT /api/v1/notifications/preferences
func (h *NotificationPrefsHandler) UpsertPreferences(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	var req struct {
		EmailEnabled       bool   `json:"email_enabled"`
		EmailAddress       string `json:"email_address"`
		MinSeverity        string `json:"min_severity"`
		NotifyIncidents    *bool  `json:"notify_incidents"`
		NotifyAgentOffline *bool  `json:"notify_agent_offline"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの形式が不正です"})
		return
	}

	// Validate min_severity
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if req.MinSeverity != "" && !valid[req.MinSeverity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "min_severity は critical / high / medium / low のいずれかです"})
		return
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "critical"
	}

	notifyIncidents := true
	if req.NotifyIncidents != nil {
		notifyIncidents = *req.NotifyIncidents
	}
	notifyAgentOffline := false
	if req.NotifyAgentOffline != nil {
		notifyAgentOffline = *req.NotifyAgentOffline
	}

	p := &store.NotificationPrefs{
		UserID:             userIDStr,
		EmailEnabled:       req.EmailEnabled,
		EmailAddress:       req.EmailAddress,
		MinSeverity:        req.MinSeverity,
		NotifyIncidents:    notifyIncidents,
		NotifyAgentOffline: notifyAgentOffline,
	}

	updated, err := h.store.Upsert(c.Request.Context(), p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定の保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, updated)
}
