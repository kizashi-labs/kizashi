package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// NotificationHistoryHandler exposes notification send history.
type NotificationHistoryHandler struct {
	Store *store.NotificationHistoryStore
}

func NewNotificationHistoryHandler(s *store.NotificationHistoryStore) *NotificationHistoryHandler {
	return &NotificationHistoryHandler{Store: s}
}

// List returns paginated notification history.
// GET /api/v1/notification-history?page=1&per_page=50
func (h *NotificationHistoryHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	entries, total, err := h.Store.List(c.Request.Context(), perPage, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "履歴の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":     entries,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Stats returns aggregated stats.
// GET /api/v1/notification-history/stats?days=7
func (h *NotificationHistoryHandler) Stats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days < 1 || days > 90 {
		days = 7
	}
	stats, err := h.Store.Stats(c.Request.Context(), days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "統計の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, stats)
}
