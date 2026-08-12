package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
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

	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Mark the event as blocked via raw_data update.
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE events
		SET raw_data = raw_data || '{"blocked": true}'::jsonb
		WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to block threat"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"blocked": true,
		"message": "threat marked as blocked",
	})
}
