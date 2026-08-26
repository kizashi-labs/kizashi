package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	store *store.DashboardStore
}

func NewDashboardHandler(s *store.DashboardStore) *DashboardHandler {
	return &DashboardHandler{store: s}
}

// GetLayout handles GET /api/v1/dashboard/layout
func (h *DashboardHandler) GetLayout(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	layout, err := h.store.Get(c.Request.Context(), userID)
	if err != nil {
		// Return default layout if not found
		c.JSON(http.StatusOK, gin.H{
			"widgets":    json.RawMessage(`[]`),
			"is_default": true,
		})
		return
	}
	c.JSON(http.StatusOK, layout)
}

// SaveLayout handles PUT /api/v1/dashboard/layout
func (h *DashboardHandler) SaveLayout(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	var body struct {
		Widgets json.RawMessage `json:"widgets"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Widgets == nil {
		body.Widgets = json.RawMessage("[]")
	}
	layout, err := h.store.Upsert(c.Request.Context(), userID, body.Widgets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "レイアウトの保存に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, layout)
}
