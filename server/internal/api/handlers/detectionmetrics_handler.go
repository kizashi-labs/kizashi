package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detectionmetrics"
)

// DetectionMetricsHandler exposes detection performance metrics endpoints.
type DetectionMetricsHandler struct {
	tracker *detectionmetrics.Tracker
}

// NewDetectionMetricsHandler creates a new DetectionMetricsHandler.
func NewDetectionMetricsHandler(pool *pgxpool.Pool) *DetectionMetricsHandler {
	return &DetectionMetricsHandler{
		tracker: detectionmetrics.NewTracker(pool),
	}
}

// GetMetrics handles GET /api/v1/admin/detection-metrics
// Query params: period (24h/7d/30d, default 7d)
func (h *DetectionMetricsHandler) GetMetrics(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	switch period {
	case "24h", "7d", "30d":
		// valid
	default:
		period = "7d"
	}

	metrics, err := h.tracker.Calculate(c.Request.Context(), period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate detection metrics"})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

// GetMITRECoverage handles GET /api/v1/admin/detection-metrics/mitre-coverage
func (h *DetectionMetricsHandler) GetMITRECoverage(c *gin.Context) {
	coverage, err := h.tracker.GetMITRECoverage(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch MITRE coverage"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"mitre_coverage": coverage,
	})
}

// GetTrend handles GET /api/v1/admin/detection-metrics/trend
// Query params: period (24h/7d/30d, default 30d)
func (h *DetectionMetricsHandler) GetTrend(c *gin.Context) {
	period := c.DefaultQuery("period", "30d")
	switch period {
	case "24h", "7d", "30d":
		// valid
	default:
		period = "30d"
	}

	trend, err := h.tracker.GetTrend(c.Request.Context(), period)
	if err != nil {
		slog.Error("detection_metrics: 検知件数の推移を読めませんでした",
			"period", period, "error", err)
		ReadFailure(c, err, gin.H{"period": period, "trend": []any{}, "count": 0})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"period": period,
		"trend":  trend,
		"count":  len(trend),
	})
}
