package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityMetricsHistoryHandler struct{ pool *pgxpool.Pool }

func NewSecurityMetricsHistoryHandler(pool *pgxpool.Pool) *SecurityMetricsHistoryHandler {
	return &SecurityMetricsHistoryHandler{pool: pool}
}

func (h *SecurityMetricsHistoryHandler) GetMetric(c *gin.Context) {
	metricName := c.Query("name")
	period := c.DefaultQuery("period", "7d")

	var interval string
	switch period {
	case "1d":
		interval = "1 day"
	case "30d":
		interval = "30 days"
	default:
		interval = "7 days"
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT metric_name, metric_value, metric_unit, recorded_at
		FROM security_metrics_history
		WHERE ($1 = '' OR metric_name = $1)
		  AND recorded_at >= NOW() - $2::interval
		ORDER BY recorded_at ASC
		LIMIT 1000
	`, metricName, interval)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"metrics": []any{}})
		return
	}
	defer rows.Close()

	type Point struct {
		MetricName  string  `json:"metric_name"`
		MetricValue float64 `json:"metric_value"`
		MetricUnit  string  `json:"metric_unit"`
		RecordedAt  string  `json:"recorded_at"`
	}
	var list []Point
	for rows.Next() {
		var p Point
		var recordedAt time.Time
		if err := rows.Scan(&p.MetricName, &p.MetricValue, &p.MetricUnit, &recordedAt); err != nil {
			continue
		}
		p.RecordedAt = recordedAt.UTC().Format(time.RFC3339)
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Point{}
	}
	c.JSON(http.StatusOK, gin.H{"metrics": list, "period": period})
}

func (h *SecurityMetricsHistoryHandler) ListMetricNames(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT DISTINCT metric_name FROM security_metrics_history ORDER BY metric_name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"names": []any{}})
		return
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			continue
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if names == nil {
		names = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"names": names})
}

func (h *SecurityMetricsHistoryHandler) RecordMetric(c *gin.Context) {
	var req struct {
		MetricName  string  `json:"metric_name" binding:"required"`
		MetricValue float64 `json:"metric_value"`
		MetricUnit  string  `json:"metric_unit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO security_metrics_history (metric_name, metric_value, metric_unit)
		VALUES ($1,$2,$3) RETURNING id
	`, req.MetricName, req.MetricValue, req.MetricUnit).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}
