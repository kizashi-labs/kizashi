package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TIFeedSyncHandler struct {
	pool *pgxpool.Pool
}

func NewTIFeedSyncHandler(pool *pgxpool.Pool) *TIFeedSyncHandler {
	return &TIFeedSyncHandler{pool: pool}
}

type FeedSyncHistory struct {
	ID         string    `json:"id"`
	FeedID     string    `json:"feed_id"`
	SyncedAt   time.Time `json:"synced_at"`
	EntryCount int       `json:"entry_count"`
	DurationMs int       `json:"duration_ms"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
}

// GET /api/v1/threat-feeds/:id/history
func (h *TIFeedSyncHandler) GetHistory(c *gin.Context) {
	feedID := c.Param("id")
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, feed_id, synced_at, entry_count, duration_ms, success, COALESCE(error,'')
		 FROM threat_feed_sync_history
		 WHERE feed_id=$1 ORDER BY synced_at DESC LIMIT 50`,
		feedID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	var history []FeedSyncHistory
	for rows.Next() {
		var h FeedSyncHistory
		if err := rows.Scan(&h.ID, &h.FeedID, &h.SyncedAt, &h.EntryCount, &h.DurationMs, &h.Success, &h.Error); err != nil {
			slog.Warn("ti_feed: sync history scan error", "error", err)
			continue
		}
		history = append(history, h)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	if history == nil {
		history = []FeedSyncHistory{}
	}
	c.JSON(http.StatusOK, history)
}

// GET /api/v1/threat-feeds/stats
func (h *TIFeedSyncHandler) GetStats(c *gin.Context) {
	var totalFeeds, activeFeeds, totalIOCs int
	ctx := c.Request.Context()
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(CASE WHEN enabled THEN 1 END) FROM threat_feeds`).
		Scan(&totalFeeds, &activeFeeds); err != nil {
		slog.Warn("ti_feed: threat_feeds 統計取得に失敗しました", "error", err)
	}
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries`).Scan(&totalIOCs); err != nil {
		slog.Warn("ti_feed: ioc_entries 統計取得に失敗しました", "error", err)
	}

	var lastSync *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT MAX(synced_at) FROM threat_feed_sync_history WHERE success=TRUE`,
	).Scan(&lastSync); err != nil && err.Error() != "no rows in result set" {
		slog.Warn("ti_feed: 最終同期時刻の取得に失敗しました", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_feeds":  totalFeeds,
		"active_feeds": activeFeeds,
		"total_iocs":   totalIOCs,
		"last_sync":    lastSync,
	})
}
