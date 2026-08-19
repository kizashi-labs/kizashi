package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MetricsHistoryHandler manages security metrics recording and querying.
type MetricsHistoryHandler struct {
	pool *pgxpool.Pool
}

// NewMetricsHistoryHandler creates a new MetricsHistoryHandler.
func NewMetricsHistoryHandler(pool *pgxpool.Pool) *MetricsHistoryHandler {
	return &MetricsHistoryHandler{pool: pool}
}

// Record inserts a new metric data point.
// POST /metrics
func (h *MetricsHistoryHandler) Record(c *gin.Context) {
	var req struct {
		MetricName  string                 `json:"metric_name" binding:"required"`
		MetricValue float64                `json:"metric_value"`
		Dimensions  map[string]interface{} `json:"dimensions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	dimJSON := metricsEncodeDimensions(req.Dimensions)

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO security_metrics (metric_name, metric_value, dimensions)
		 VALUES ($1, $2, $3::jsonb)
		 RETURNING id`,
		req.MetricName, req.MetricValue, dimJSON,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "メトリクスを記録しました"})
}

// Query returns metric data for a given name and time range.
// GET /metrics/query?metric_name=...&from=...&to=...&period=raw|hourly|daily
func (h *MetricsHistoryHandler) Query(c *gin.Context) {
	metricName := c.Query("metric_name")
	if metricName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "metric_name パラメータが必要です"})
		return
	}

	period := c.DefaultQuery("period", "raw")
	fromStr := c.Query("from")
	toStr := c.Query("to")

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	ctx := c.Request.Context()

	type DataPoint struct {
		Timestamp time.Time `json:"timestamp"`
		Value     float64   `json:"value"`
	}

	var dataPoints []DataPoint

	if period == "raw" {
		rows, err := h.pool.Query(ctx,
			`SELECT recorded_at, metric_value
			 FROM security_metrics
			 WHERE metric_name = $1
			   AND recorded_at >= $2
			   AND recorded_at <= $3
			 ORDER BY recorded_at ASC
			 LIMIT 1000`,
			metricName, from, to,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		defer rows.Close()
		for rows.Next() {
			var dp DataPoint
			if err := rows.Scan(&dp.Timestamp, &dp.Value); err == nil {
				dataPoints = append(dataPoints, dp)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
	} else {
		// hourly or daily — use aggregates table
		rows, err := h.pool.Query(ctx,
			`SELECT period_start, avg_value
			 FROM metric_aggregates
			 WHERE metric_name = $1
			   AND period = $2
			   AND period_start >= $3
			   AND period_start <= $4
			 ORDER BY period_start ASC
			 LIMIT 1000`,
			metricName, period, from, to,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		defer rows.Close()
		for rows.Next() {
			var dp DataPoint
			if err := rows.Scan(&dp.Timestamp, &dp.Value); err == nil {
				dataPoints = append(dataPoints, dp)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
	}

	if dataPoints == nil {
		dataPoints = []DataPoint{}
	}

	c.JSON(http.StatusOK, gin.H{
		"metric_name": metricName,
		"period":      period,
		"from":        from,
		"to":          to,
		"data":        dataPoints,
	})
}

// GetLatest returns the latest value for each distinct metric name.
// GET /metrics/latest
func (h *MetricsHistoryHandler) GetLatest(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT DISTINCT ON (metric_name) metric_name, metric_value, recorded_at
		 FROM security_metrics
		 ORDER BY metric_name, recorded_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type LatestMetric struct {
		MetricName  string    `json:"metric_name"`
		MetricValue float64   `json:"metric_value"`
		RecordedAt  time.Time `json:"recorded_at"`
	}

	var metrics []LatestMetric
	for rows.Next() {
		var m LatestMetric
		if err := rows.Scan(&m.MetricName, &m.MetricValue, &m.RecordedAt); err == nil {
			metrics = append(metrics, m)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if metrics == nil {
		metrics = []LatestMetric{}
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics, "total": len(metrics)})
}

// GetSummary returns key security metrics for the last 24h.
// GET /metrics/summary
func (h *MetricsHistoryHandler) GetSummary(c *gin.Context) {
	ctx := c.Request.Context()
	since := time.Now().Add(-24 * time.Hour)

	summary := map[string]interface{}{
		"period": "24h",
		"since":  since,
	}

	// alert_count
	var alertCount int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= $1`, since,
	).Scan(&alertCount)) {
		return
	}
	summary["alert_count"] = alertCount

	// agent_count (online)
	var agentCount int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE status = 'online'`,
	).Scan(&agentCount)) {
		return
	}
	summary["agent_count"] = agentCount

	// mttd_hours — アラート作成からトリアージ（investigating）までの平均時間
	var mttdHours float64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(
				EXTRACT(EPOCH FROM (asc2.changed_at - a.created_at)) / 3600
			), 0)
			FROM alerts a
			JOIN (
				SELECT DISTINCT ON (alert_id) alert_id, changed_at
				FROM alert_status_changes
				WHERE to_status IN ('investigating', 'in_progress')
				ORDER BY alert_id, changed_at ASC
			) asc2 ON asc2.alert_id = a.id
			WHERE a.created_at >= $1`,
		since,
	).Scan(&mttdHours)) {
		return
	}
	summary["mttd_hours"] = mttdHours

	// mttr_hours — mean time to resolve
	var mttrHours float64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0), 0)
			 FROM alerts
			 WHERE resolved_at IS NOT NULL AND created_at >= $1`,
		since,
	).Scan(&mttrHours)) {
		return
	}
	summary["mttr_hours"] = mttrHours

	// threat_detection_rate — alerts / events * 100
	// events の時刻列は `time`。`timestamp` は存在せず、以前はこのクエリが常に
	// 失敗して event_count / threat_detection_rate が 0 固定になっていた。
	var eventCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE time >= $1`, since,
	).Scan(&eventCount); err != nil {
		slog.Warn("metrics summary: イベント件数の取得に失敗", "error", err)
	}
	var threatDetectionRate float64
	if eventCount > 0 {
		threatDetectionRate = float64(alertCount) / float64(eventCount) * 100.0
	}
	summary["threat_detection_rate"] = threatDetectionRate
	summary["event_count"] = eventCount

	c.JSON(http.StatusOK, summary)
}

// ListMetricNames returns distinct metric names with their latest value.
// GET /metrics/names
func (h *MetricsHistoryHandler) ListMetricNames(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT DISTINCT ON (metric_name) metric_name, metric_value, recorded_at
		 FROM security_metrics
		 ORDER BY metric_name, recorded_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type MetricInfo struct {
		MetricName   string    `json:"metric_name"`
		LatestValue  float64   `json:"latest_value"`
		LastRecorded time.Time `json:"last_recorded"`
		Description  string    `json:"description"`
	}

	var names []MetricInfo
	for rows.Next() {
		var m MetricInfo
		if err := rows.Scan(&m.MetricName, &m.LatestValue, &m.LastRecorded); err == nil {
			names = append(names, m)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if names == nil {
		names = []MetricInfo{}
	}

	c.JSON(http.StatusOK, gin.H{"metric_names": names, "total": len(names)})
}

// metricsEncodeDimensions converts a map to a JSON string for JSONB storage.
func metricsEncodeDimensions(dims map[string]interface{}) string {
	if dims == nil {
		return "{}"
	}
	b, err := json.Marshal(dims)
	if err != nil {
		return "{}"
	}
	return string(b)
}
