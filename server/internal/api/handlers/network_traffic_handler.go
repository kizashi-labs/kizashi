package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetworkTrafficHandler provides network traffic statistics for the /network-traffic page.
// GET /api/v1/network-traffic/stats
type NetworkTrafficHandler struct {
	pool *pgxpool.Pool
}

func NewNetworkTrafficHandler(pool *pgxpool.Pool) *NetworkTrafficHandler {
	return &NetworkTrafficHandler{pool: pool}
}

// GetStats returns aggregate network traffic statistics.
// GET /api/v1/network-traffic/stats
func (h *NetworkTrafficHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	stats := gin.H{
		"total_flows":      0,
		"bandwidth_gb":     0.0,
		"top_protocol":     "—",
		"suspicious_flows": 0,
	}

	// Check for NTA detections table.
	var ntaExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='nta_detections')`).Scan(&ntaExists)

	if ntaExists {
		var suspicious int
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE detected_at > NOW()-INTERVAL '24 hours'`).Scan(&suspicious)
		stats["suspicious_flows"] = suspicious
	}

	// Try to get network events from events table.
	var eventsExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='events')`).Scan(&eventsExists)

	if eventsExists {
		// events の実際の列は event_type / time / raw_data (migration 002)。
		// 以前は type / created_at / event_data,data,metadata という存在しない列を
		// 参照しており、両クエリとも常に失敗して total_flows と top_protocol が
		// 0 / "TCP" 固定になっていた。
		var total int
		if err := h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM events WHERE event_type='network' AND time > NOW()-INTERVAL '24h'`,
		).Scan(&total); err != nil {
			slog.Warn("network traffic: ネットワークイベント数の取得に失敗", "error", err)
		}

		var topProto string
		if err := h.pool.QueryRow(ctx, `
			SELECT COALESCE(raw_data->>'protocol', 'TCP')
			FROM events
			WHERE event_type='network' AND time > NOW()-INTERVAL '24h'
			GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1`).Scan(&topProto); err != nil {
			slog.Warn("network traffic: 主要プロトコルの取得に失敗", "error", err)
		}

		if topProto == "" {
			topProto = "TCP"
		}

		stats["total_flows"] = total
		stats["top_protocol"] = topProto
		// Estimate bandwidth: rough 1KB per event average
		stats["bandwidth_gb"] = float64(total) * 0.001 / 1024.0
	}

	c.JSON(http.StatusOK, stats)
}
