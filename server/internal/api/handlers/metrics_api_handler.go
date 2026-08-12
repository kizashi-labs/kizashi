package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MetricsAPIHandler handles metrics endpoint requests.
type MetricsAPIHandler struct {
	pool *pgxpool.Pool
}

// NewMetricsAPIHandler creates a new MetricsAPIHandler.
func NewMetricsAPIHandler(pool *pgxpool.Pool) *MetricsAPIHandler {
	return &MetricsAPIHandler{pool: pool}
}

// tableExists checks if a table exists in pg_tables.
func (h *MetricsAPIHandler) tableExists(ctx context.Context, table string) bool {
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=$1)`,
		table,
	).Scan(&exists)
	return err == nil && exists
}

// AlertTrends handles GET /api/v1/metrics/alert-trends?period=hour|day|week
func (h *MetricsAPIHandler) AlertTrends(c *gin.Context) {
	period := c.DefaultQuery("period", "day")

	type DataPoint struct {
		Timestamp string `json:"timestamp"`
		Count     int    `json:"count"`
	}

	data := []DataPoint{}

	if !h.tableExists(c.Request.Context(), "alerts") {
		c.JSON(http.StatusOK, gin.H{"period": period, "data": data})
		return
	}

	var truncExpr string
	var interval string
	switch period {
	case "hour":
		truncExpr = "minute"
		interval = "1 hour"
	case "week":
		truncExpr = "day"
		interval = "7 days"
	default: // day
		period = "day"
		truncExpr = "hour"
		interval = "24 hours"
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT date_trunc($1, created_at) AS bucket, COUNT(*) AS cnt
		FROM alerts
		WHERE created_at >= NOW() - $2::interval
		GROUP BY bucket
		ORDER BY bucket ASC
	`, truncExpr, interval)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"period": period, "data": data})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ts time.Time
		var cnt int
		if err := rows.Scan(&ts, &cnt); err != nil {
			continue
		}
		data = append(data, DataPoint{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Count:     cnt,
		})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"period": period, "data": data})
}

// TopAgents handles GET /api/v1/metrics/top-agents
func (h *MetricsAPIHandler) TopAgents(c *gin.Context) {
	type AgentStat struct {
		AgentID    string `json:"agent_id"`
		Hostname   string `json:"hostname"`
		AlertCount int    `json:"alert_count"`
	}

	agents := []AgentStat{}

	if !h.tableExists(c.Request.Context(), "alerts") {
		c.JSON(http.StatusOK, gin.H{"agents": agents})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT a.agent_id::text, COALESCE(ag.hostname, a.agent_id::text), COUNT(*) AS cnt
		FROM alerts a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.agent_id IS NOT NULL
		GROUP BY a.agent_id, ag.hostname
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"agents": agents})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var s AgentStat
		if err := rows.Scan(&s.AgentID, &s.Hostname, &s.AlertCount); err != nil {
			continue
		}
		agents = append(agents, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

// DetectionStats handles GET /api/v1/metrics/detection-stats
func (h *MetricsAPIHandler) DetectionStats(c *gin.Context) {
	type Stats struct {
		TotalAlerts        int     `json:"total_alerts"`
		ResolutionRate     float64 `json:"resolution_rate"`
		AvgResolutionHours float64 `json:"avg_resolution_hours"`
		FalsePositiveRate  float64 `json:"false_positive_rate"`
	}

	stats := Stats{}

	if !h.tableExists(c.Request.Context(), "alerts") {
		c.JSON(http.StatusOK, stats)
		return
	}

	row := h.pool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) AS total,
			ROUND(
				CASE WHEN COUNT(*) = 0 THEN 0
				ELSE COUNT(*) FILTER (WHERE status IN ('resolved','closed')) * 1.0 / COUNT(*)
				END, 4
			) AS resolution_rate,
			COALESCE(
				AVG(
					EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600.0
				) FILTER (WHERE status IN ('resolved','closed')),
				0
			) AS avg_resolution_hours,
			ROUND(
				CASE WHEN COUNT(*) = 0 THEN 0
				ELSE COUNT(*) FILTER (WHERE status = 'false_positive') * 1.0 / COUNT(*)
				END, 4
			) AS false_positive_rate
		FROM alerts
	`)

	if err := row.Scan(&stats.TotalAlerts, &stats.ResolutionRate, &stats.AvgResolutionHours, &stats.FalsePositiveRate); err != nil {
		c.JSON(http.StatusOK, stats)
		return
	}

	c.JSON(http.StatusOK, stats)
}

// AgentStats handles GET /api/v1/metrics/agent-stats
func (h *MetricsAPIHandler) AgentStats(c *gin.Context) {
	type AgentStats struct {
		Total   int `json:"total"`
		Online  int `json:"online"`
		Offline int `json:"offline"`
		Stale   int `json:"stale"`
	}

	stats := AgentStats{}

	if !h.tableExists(c.Request.Context(), "agents") {
		c.JSON(http.StatusOK, stats)
		return
	}

	row := h.pool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '5 minutes') AS online,
			COUNT(*) FILTER (WHERE last_seen < NOW() - INTERVAL '1 hour' OR last_seen IS NULL) AS offline,
			COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '1 hour' AND last_seen < NOW() - INTERVAL '5 minutes') AS stale
		FROM agents
	`)

	if err := row.Scan(&stats.Total, &stats.Online, &stats.Offline, &stats.Stale); err != nil {
		c.JSON(http.StatusOK, stats)
		return
	}

	c.JSON(http.StatusOK, stats)
}
