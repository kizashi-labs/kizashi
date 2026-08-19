package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardStatsHandler provides time-series and aggregated statistics for the dashboard.
type DashboardStatsHandler struct {
	pool *pgxpool.Pool
}

// NewDashboardStatsHandler creates a new DashboardStatsHandler.
func NewDashboardStatsHandler(pool *pgxpool.Pool) *DashboardStatsHandler {
	return &DashboardStatsHandler{pool: pool}
}

// AlertTrend handles GET /api/v1/dashboard/alert-trend
// Query param: days (default 7, max 30)
// Returns: { trend: [{ date, count, critical }] }
func (h *DashboardStatsHandler) AlertTrend(c *gin.Context) {
	days := 7
	if d := c.Query("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			if v > 30 {
				v = 30
			}
			days = v
		}
	}

	type TrendPoint struct {
		Date     string `json:"date"`
		Count    int    `json:"count"`
		Critical int    `json:"critical"`
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT
			DATE(created_at)::text,
			COUNT(*),
			COUNT(*) FILTER (WHERE severity >= 9)
		FROM alerts
		WHERE created_at > NOW() - ($1 || ' days')::INTERVAL
		GROUP BY DATE(created_at)
		ORDER BY 1
	`, strconv.Itoa(days))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query alert trend"})
		return
	}
	defer rows.Close()

	trend := make([]TrendPoint, 0)
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Date, &p.Count, &p.Critical); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan alert trend row"})
			return
		}
		trend = append(trend, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "alert trend query error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"trend": trend})
}

// TopEndpoints handles GET /api/v1/dashboard/top-endpoints
// Returns top 10 agents by alert count in the last 7 days.
// Response: { endpoints: [{ agent_id, hostname, alert_count, last_alert }] }
func (h *DashboardStatsHandler) TopEndpoints(c *gin.Context) {
	type EndpointStat struct {
		AgentID    string     `json:"agent_id"`
		Hostname   string     `json:"hostname"`
		AlertCount int        `json:"alert_count"`
		LastAlert  *time.Time `json:"last_alert"`
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT
			a.agent_id,
			COALESCE(ag.hostname, a.agent_id::text) AS hostname,
			COUNT(*) AS alert_count,
			MAX(a.created_at) AS last_alert
		FROM alerts a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.created_at > NOW() - INTERVAL '7 days'
		  AND a.agent_id IS NOT NULL
		GROUP BY a.agent_id, ag.hostname
		ORDER BY alert_count DESC
		LIMIT 10
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query top endpoints"})
		return
	}
	defer rows.Close()

	endpoints := make([]EndpointStat, 0)
	for rows.Next() {
		var ep EndpointStat
		if err := rows.Scan(&ep.AgentID, &ep.Hostname, &ep.AlertCount, &ep.LastAlert); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan top endpoints row"})
			return
		}
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "top endpoints query error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"endpoints": endpoints})
}

// DetectionRate handles GET /api/v1/dashboard/detection-rate
// Returns: { total_alerts_7d, resolved_7d, resolution_rate, avg_resolution_hours, open_critical }
func (h *DashboardStatsHandler) DetectionRate(c *gin.Context) {
	type DetectionStats struct {
		TotalAlerts7d      int     `json:"total_alerts_7d"`
		Resolved7d         int     `json:"resolved_7d"`
		ResolutionRate     float64 `json:"resolution_rate"`
		AvgResolutionHours float64 `json:"avg_resolution_hours"`
		OpenCritical       int     `json:"open_critical"`
	}

	var stats DetectionStats

	row := h.pool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) AS total_alerts_7d,
			COUNT(*) FILTER (WHERE status = 'resolved') AS resolved_7d,
			CASE WHEN COUNT(*) = 0 THEN 0
			     ELSE ROUND(COUNT(*) FILTER (WHERE status = 'resolved')::numeric / COUNT(*) * 100, 2)
			END AS resolution_rate,
			COALESCE(
				AVG(
					EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600.0
				) FILTER (WHERE status = 'resolved' AND updated_at > created_at),
				0
			) AS avg_resolution_hours,
			COUNT(*) FILTER (WHERE status <> 'resolved' AND severity >= 9) AS open_critical
		FROM alerts
		WHERE created_at > NOW() - INTERVAL '7 days'
	`)

	if err := row.Scan(
		&stats.TotalAlerts7d,
		&stats.Resolved7d,
		&stats.ResolutionRate,
		&stats.AvgResolutionHours,
		&stats.OpenCritical,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query detection rate"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Summary handles GET /api/v1/dashboard/summary
// Returns all key KPIs: agents_online, open_alerts, open_incidents, critical_alerts_24h
func (h *DashboardStatsHandler) Summary(c *gin.Context) {
	type SummaryStats struct {
		AgentsOnline      int `json:"agents_online"`
		OpenAlerts        int `json:"open_alerts"`
		OpenIncidents     int `json:"open_incidents"`
		CriticalAlerts24h int `json:"critical_alerts_24h"`
	}

	var stats SummaryStats

	// この4つは SOC が最初に開く画面の数字です。以前はどれも、クエリが
	// 失敗したら 0 を入れて先へ進み、最後に 200 で返していました。
	//
	//	if err := agentRow.Scan(&stats.AgentsOnline); err != nil {
	//		stats.AgentsOnline = 0
	//	}
	//
	// 「オンライン0台・未対応アラート0件・未解決インシデント0件」は、
	// 落ち着いた朝の画面と見分けが付きません。分岐そのものが応答を返さず、
	// 通常の経路が 200 を返すので、空で返す実装を探す検査にも映りません。
	for _, q := range []struct {
		what string
		sql  string
		dst  *int
	}{
		{"オンラインのエージェント数", `SELECT COUNT(*) FROM agents WHERE status = 'online'`, &stats.AgentsOnline},
		{"未対応のアラート数", `SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'dismissed')`, &stats.OpenAlerts},
		{"未解決のインシデント数", `SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved', 'closed')`, &stats.OpenIncidents},
		{"24時間以内の重大アラート数", `SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at > NOW() - INTERVAL '24 hours'`, &stats.CriticalAlerts24h},
	} {
		if err := h.pool.QueryRow(c.Request.Context(), q.sql).Scan(q.dst); err != nil {
			slog.Error("dashboard summary: 取得できませんでした", "what", q.what, "error", err)
			ReadFailure(c, err, stats)
			return
		}
	}

	c.JSON(http.StatusOK, stats)
}

// clampDays は days パラメータを 1–30 の範囲に収める純粋関数。
// ゼロ以下は 7 (デフォルト) に、30 超は 30 に補正する。
func clampDays(d int) int {
	if d <= 0 {
		return 7
	}
	if d > 30 {
		return 30
	}
	return d
}
