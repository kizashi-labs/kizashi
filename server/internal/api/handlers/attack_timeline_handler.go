package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/timeline"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AttackTimelineHandler handles attack timeline API endpoints.
type AttackTimelineHandler struct {
	builder *timeline.Builder
	pool    *pgxpool.Pool
}

// NewAttackTimelineHandler creates a new AttackTimelineHandler.
func NewAttackTimelineHandler(pool *pgxpool.Pool) *AttackTimelineHandler {
	return &AttackTimelineHandler{builder: timeline.NewBuilder(pool), pool: pool}
}

// GetAgentTimeline handles GET /api/v1/agents/:id/attack-timeline?hours=24
func (h *AttackTimelineHandler) GetAgentTimeline(c *gin.Context) {
	agentID := c.Param("id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}

	tl, err := h.builder.BuildAgentTimeline(c.Request.Context(), agentID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タイムラインの構築に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, tl)
}

// GetIncidentTimeline handles GET /api/v1/admin/incidents/:id/timeline
func (h *AttackTimelineHandler) GetIncidentTimeline(c *gin.Context) {
	incidentID := c.Param("id")

	tl, err := h.builder.BuildIncidentTimeline(c.Request.Context(), incidentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "インシデントタイムラインの構築に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, tl)
}

// GetAlertTimeline handles GET /api/v1/alerts/:id/timeline
// Returns the full timeline plus hourly bucket counts for bar chart rendering.
func (h *AttackTimelineHandler) GetAlertTimeline(c *gin.Context) {
	alertID := c.Param("id")

	tl, err := h.builder.BuildAlertTimeline(c.Request.Context(), alertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートタイムラインの構築に失敗しました"})
		return
	}

	// Build per-hour alert counts and raw event counts for the dual-layer bar chart.
	alertCounts, eventCounts, _ := h.buildAlertHourlyStats(c.Request.Context(), tl.AgentID, tl.StartTime, tl.EndTime)

	c.JSON(http.StatusOK, gin.H{
		"agent_id":      tl.AgentID,
		"hostname":      tl.Hostname,
		"start_time":    tl.StartTime,
		"end_time":      tl.EndTime,
		"events":        tl.Events,
		"total_events":  tl.TotalEvents,
		"alert_count":   tl.AlertCount,
		"attack_phases": tl.AttackPhases,
		// hourly_alerts: alert count per UTC hour (primary: shown as coloured bars)
		"hourly_alerts": alertCounts,
		// hourly_events: raw telemetry count per UTC hour (secondary: activity background)
		"hourly_events": eventCounts,
	})
}

// buildAlertHourlyStats returns per-hour alert counts and raw event counts
// for the given agent and time window.
// alert_counts  = number of alerts created in that UTC hour (shown as-is)
// event_counts  = raw telemetry events (for activity background reference)
func (h *AttackTimelineHandler) buildAlertHourlyStats(ctx context.Context, agentID string, from, to time.Time) (alertCounts []int, eventCounts []int, err error) {
	alertCounts = make([]int, 24)
	eventCounts = make([]int, 24)

	if h.pool == nil || agentID == "" || from.IsZero() {
		return
	}

	// Raw telemetry event counts per hour
	evRows, err := h.pool.Query(ctx, `
		SELECT EXTRACT(HOUR FROM time)::int AS hr, COUNT(*)::int
		FROM events
		WHERE agent_id = $1::uuid
		  AND time BETWEEN $2 AND $3
		GROUP BY hr`, agentID, from, to)
	if err == nil {
		defer evRows.Close()
		for evRows.Next() {
			var hr, cnt int
			if scanErr := evRows.Scan(&hr, &cnt); scanErr == nil && hr >= 0 && hr < 24 {
				eventCounts[hr] = cnt
			}
		}
		if err := evRows.Err(); err != nil {
			slog.Warn("buildAlertHourlyStats: evRows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
		}
	}

	// Alert counts per hour (from alerts table)
	alRows, qErr := h.pool.Query(ctx, `
		SELECT EXTRACT(HOUR FROM created_at)::int AS hr, COUNT(*)::int
		FROM alerts
		WHERE agent_id = $1::uuid
		  AND created_at BETWEEN $2 AND $3
		GROUP BY hr`, agentID, from, to)
	if qErr == nil {
		defer alRows.Close()
		for alRows.Next() {
			var hr, cnt int
			if scanErr := alRows.Scan(&hr, &cnt); scanErr == nil && hr >= 0 && hr < 24 {
				alertCounts[hr] = cnt
			}
		}
		if err := alRows.Err(); err != nil {
			slog.Warn("buildAlertHourlyStats: alRows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
		}
	}

	return alertCounts, eventCounts, nil
}
