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

// defaultNotificationPerPage / maxNotificationPerPage bound one page.
const (
	defaultNotificationPerPage = 50
	maxNotificationPerPage     = 200
)

// clampNotificationPage bounds the page parameters and derives the offset.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// `internal/store` の検査ファイルには、これと違う値の写し（既定 20、
// 200 超は 200 に丸める）が置いてあり、そちらだけが試されていました。
//
// 範囲外を既定に戻すのは、0 を通すと 0 件返り、**「履歴が無い」と
// 見分けが付かなくなる**からです。負のページを 1 に寄せるのは、
// 負の OFFSET を Postgres が拒否して一覧が丸ごとエラーになるからです。
func clampNotificationPage(page, perPage int) (int, int, int) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > maxNotificationPerPage {
		perPage = defaultNotificationPerPage
	}
	return page, perPage, (page - 1) * perPage
}

// List returns paginated notification history.
// GET /api/v1/notification-history?page=1&per_page=50
func (h *NotificationHistoryHandler) List(c *gin.Context) {
	rawPage, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	rawPerPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, perPage, offset := clampNotificationPage(rawPage, rawPerPage)

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
