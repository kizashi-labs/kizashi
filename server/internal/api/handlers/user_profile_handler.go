package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// UserProfileHandler serves per-user profile endpoints that live under
// /api/v1/users/me/... (login history, API activity, notification prefs).
type UserProfileHandler struct {
	audit      *store.AuditStore
	notifPrefs *store.NotificationPrefStore
}

// NewUserProfileHandler creates a UserProfileHandler.
func NewUserProfileHandler(audit *store.AuditStore, notifPrefs *store.NotificationPrefStore) *UserProfileHandler {
	return &UserProfileHandler{audit: audit, notifPrefs: notifPrefs}
}

// ---------- Login History ----------

// LoginHistory returns recent login events for the current user.
// GET /api/v1/users/me/login-history?limit=20
func (h *UserProfileHandler) LoginHistory(c *gin.Context) {
	userID := currentUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	limit := intQuery(c, "limit", 20)

	logs, _, err := h.audit.List(c.Request.Context(), limit, 0, store.AuditFilter{
		UserID: userID,
		Action: "login",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ログイン履歴の取得に失敗しました"})
		return
	}

	// Map to the shape the frontend expects.
	type loginEvent struct {
		ID        string `json:"id"`
		IPAddress string `json:"ip_address"`
		UserAgent string `json:"user_agent"`
		CreatedAt string `json:"created_at"`
		Success   bool   `json:"success"`
		Location  string `json:"location,omitempty"`
	}

	events := make([]loginEvent, 0, len(logs))
	for _, l := range logs {
		ua, _ := l.Details["user_agent"].(string)
		loc, _ := l.Details["location"].(string)
		events = append(events, loginEvent{
			ID:        l.ID,
			IPAddress: l.IPAddress,
			UserAgent: ua,
			CreatedAt: l.Timestamp.Format("2006-01-02T15:04:05Z"),
			Success:   l.StatusCode < 400,
			Location:  loc,
		})
	}

	c.JSON(http.StatusOK, events)
}

// ---------- API Activity ----------

// APIActivity returns recent API call events for the current user.
// GET /api/v1/users/me/api-activity?limit=20
func (h *UserProfileHandler) APIActivity(c *gin.Context) {
	userID := currentUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	limit := intQuery(c, "limit", 20)

	logs, _, err := h.audit.List(c.Request.Context(), limit, 0, store.AuditFilter{
		UserID: userID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "API利用状況の取得に失敗しました"})
		return
	}

	type apiCallEvent struct {
		ID        string `json:"id"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Status    int    `json:"status"`
		CreatedAt string `json:"created_at"`
	}

	events := make([]apiCallEvent, 0, len(logs))
	for _, l := range logs {
		method := l.Action
		path, _ := l.Details["path"].(string)
		if path == "" {
			path = l.ResourceID
		}
		events = append(events, apiCallEvent{
			ID:        l.ID,
			Method:    method,
			Path:      path,
			Status:    l.StatusCode,
			CreatedAt: l.Timestamp.Format("2006-01-02T15:04:05Z"),
		})
	}

	c.JSON(http.StatusOK, events)
}

// ---------- Notification Preferences ----------

// GetNotificationPrefs returns the current user's notification preferences.
// GET /api/v1/users/me/notification-prefs
func (h *UserProfileHandler) GetNotificationPrefs(c *gin.Context) {
	userID := currentUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	prefs, err := h.notifPrefs.GetByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "通知設定の取得に失敗しました"})
		return
	}

	// Map to the shape the frontend expects (event_type-based list).
	type notifPref struct {
		EventType string `json:"event_type"`
		Label     string `json:"label"`
		Email     bool   `json:"email"`
		InApp     bool   `json:"in_app"`
	}

	result := []notifPref{
		{EventType: "incidents", Label: "インシデント通知", Email: prefs.EmailEnabled && prefs.NotifyIncidents, InApp: prefs.NotifyIncidents},
		{EventType: "agent_offline", Label: "エージェントオフライン", Email: prefs.EmailEnabled && prefs.NotifyAgentOffline, InApp: prefs.NotifyAgentOffline},
		{EventType: "critical_alerts", Label: "重大アラート", Email: prefs.EmailEnabled && prefs.MinSeverity != "", InApp: true},
		{EventType: "reports", Label: "レポート完了", Email: prefs.EmailEnabled, InApp: true},
	}

	c.JSON(http.StatusOK, result)
}

// UpdateNotificationPrefs updates the current user's notification preferences.
// PUT /api/v1/users/me/notification-prefs
func (h *UserProfileHandler) UpdateNotificationPrefs(c *gin.Context) {
	userID := currentUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	var req struct {
		Prefs []struct {
			EventType string `json:"event_type"`
			Email     bool   `json:"email"`
			InApp     bool   `json:"in_app"`
		} `json:"prefs"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの形式が不正です"})
		return
	}

	// Convert event-type list to the store model.
	p := &store.NotificationPrefs{
		UserID:      userID,
		MinSeverity: "critical",
	}
	for _, pref := range req.Prefs {
		switch pref.EventType {
		case "incidents":
			p.NotifyIncidents = pref.InApp
			if pref.Email {
				p.EmailEnabled = true
			}
		case "agent_offline":
			p.NotifyAgentOffline = pref.InApp
			if pref.Email {
				p.EmailEnabled = true
			}
		case "critical_alerts":
			if pref.Email {
				p.EmailEnabled = true
			}
		}
	}

	updated, err := h.notifPrefs.Upsert(c.Request.Context(), p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "通知設定の保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, updated)
}

// ---------- helpers ----------

func currentUserID(c *gin.Context) string {
	v, _ := c.Get("user_id")
	s, _ := v.(string)
	return s
}

func intQuery(c *gin.Context, key string, fallback int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}
