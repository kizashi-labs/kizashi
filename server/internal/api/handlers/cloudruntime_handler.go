package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/cloudruntime"
)

// CloudRuntimeHandler exposes cloud workload runtime protection endpoints.
type CloudRuntimeHandler struct {
	monitor *cloudruntime.Monitor
	pool    *pgxpool.Pool
}

// NewCloudRuntimeHandler creates a new CloudRuntimeHandler.
func NewCloudRuntimeHandler(pool *pgxpool.Pool) *CloudRuntimeHandler {
	return &CloudRuntimeHandler{
		monitor: cloudruntime.NewMonitor(pool),
		pool:    pool,
	}
}

// ListThreats handles GET /api/v1/admin/cloud-runtime/threats
// Query params: hours (default 24)
func (h *CloudRuntimeHandler) ListThreats(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 {
		hours = 24
	}

	threats, err := h.monitor.ListThreats(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch runtime threats"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"threats": threats,
		"count":   len(threats),
	})
}

// GetStats handles GET /api/v1/admin/cloud-runtime/stats
func (h *CloudRuntimeHandler) GetStats(c *gin.Context) {
	stats := h.monitor.GetRuntimeStats(c.Request.Context())
	c.JSON(http.StatusOK, stats)
}

// BlockThreat handles POST /api/v1/admin/cloud-runtime/threats/:id/block
// Marks a threat as blocked in the events table (best-effort).
func (h *CloudRuntimeHandler) BlockThreat(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threat id required"})
		return
	}
	// event_id は uuid 列なので、uuid でない文字列は下のクエリで 22P02 になります。
	// それをそのまま 500 にすると、入力の誤りをサーバ障害として報告することに
	// なるため、ここで弾きます。
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threat id must be a uuid"})
		return
	}

	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Mark the event as blocked via raw_data update.
	//
	// events の主キーは event_id (uuid) で、id という列はありません。この文は
	// 42703 で拒否されており、脅威のブロック操作は毎回 500 を返していました。
	// 一覧が返す threat.id は e.event_id そのものなので、その列で更新します。
	// 文字列を uuid 列に直接束縛すると 22P02 になるため明示的にキャストします。
	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE events
		SET raw_data = raw_data || '{"blocked": true}'::jsonb
		WHERE event_id = $1::uuid`, id)
	if err != nil {
		slog.Warn("cloud runtime: 脅威のブロックに失敗しました", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to block threat"})
		return
	}
	// 該当が無ければ「ブロックした」とは答えません。0 件更新を成功として返すと、
	// 消えた脅威を止めたつもりの操作者が残ります。
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "threat not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"blocked": true,
		"message": "threat marked as blocked",
	})
}
