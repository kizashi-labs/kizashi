package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// defaultWidgetIDs defines the canonical order of dashboard widgets.
// This must stay in sync with WIDGET_IDS in the frontend dashboard page.
var defaultWidgetIDs = []string{
	"endpoint-status",
	"threat-detection",
	"charts",
	"mitre-ioc",
	"risk-quickaccess",
	"recent-alerts",
}

// DashboardPrefsHandler handles dashboard widget preference endpoints.
type DashboardPrefsHandler struct {
	store *store.DashboardPrefsStore
}

// NewDashboardPrefsHandler creates a new DashboardPrefsHandler.
func NewDashboardPrefsHandler(s *store.DashboardPrefsStore) *DashboardPrefsHandler {
	return &DashboardPrefsHandler{store: s}
}

// GetPrefs returns the authenticated user's dashboard widget preferences.
// If no preferences are saved yet, returns the default widget configuration.
//
// GET /api/v1/preferences/dashboard
func (h *DashboardPrefsHandler) GetPrefs(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	prefs, err := h.store.Get(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ダッシュボード設定の取得に失敗しました"})
		return
	}

	// No saved preferences — return defaults.
	if prefs == nil {
		widgets := make([]store.WidgetPref, len(defaultWidgetIDs))
		for i, id := range defaultWidgetIDs {
			widgets[i] = store.WidgetPref{
				ID:      id,
				Visible: true,
				Order:   i,
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"user_id": userIDStr,
			"widgets": widgets,
		})
		return
	}

	// Merge: ensure any new widget IDs not yet in the stored prefs are appended.
	storedIDs := make(map[string]bool, len(prefs.Widgets))
	for _, w := range prefs.Widgets {
		storedIDs[w.ID] = true
	}
	nextOrder := len(prefs.Widgets)
	for _, id := range defaultWidgetIDs {
		if !storedIDs[id] {
			prefs.Widgets = append(prefs.Widgets, store.WidgetPref{
				ID:      id,
				Visible: true,
				Order:   nextOrder,
			})
			nextOrder++
		}
	}

	c.JSON(http.StatusOK, prefs)
}

// UpsertPrefs saves the authenticated user's dashboard widget preferences.
//
// PUT /api/v1/preferences/dashboard
func (h *DashboardPrefsHandler) UpsertPrefs(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	var body struct {
		Widgets []store.WidgetPref `json:"widgets"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です"})
		return
	}

	prefs := store.DashboardPrefs{
		UserID:  userIDStr,
		Widgets: body.Widgets,
	}
	if prefs.Widgets == nil {
		prefs.Widgets = []store.WidgetPref{}
	}

	if err := h.store.Upsert(c.Request.Context(), prefs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ダッシュボード設定の保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, prefs)
}
