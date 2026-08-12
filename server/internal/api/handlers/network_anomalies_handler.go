package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetworkAnomaliesHandler serves network anomaly data.
// GET  /api/v1/network-anomalies
// GET  /api/v1/network-anomalies/stats
// POST /api/v1/network-anomalies/:id/suppress
type NetworkAnomaliesHandler struct {
	pool *pgxpool.Pool
}

func NewNetworkAnomaliesHandler(pool *pgxpool.Pool) *NetworkAnomaliesHandler {
	return &NetworkAnomaliesHandler{pool: pool}
}

func (h *NetworkAnomaliesHandler) tableExists(c *gin.Context) bool {
	var ok bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='network_anomalies')`).Scan(&ok)
	return ok
}

// ── Types ─────────────────────────────────────────────────────────────────────

type netAnomaly struct {
	ID               string  `json:"id"`
	Type             string  `json:"type"`
	AgentID          string  `json:"agent_id"`
	AgentHostname    string  `json:"agent_hostname"`
	Description      string  `json:"description"`
	Severity         string  `json:"severity"`
	SourceIP         string  `json:"source_ip"`
	SourcePort       *int    `json:"source_port"`
	DestIP           *string `json:"dest_ip"`
	DestPort         *int    `json:"dest_port"`
	DetectedAt       string  `json:"detected_at"`
	RelatedAlertID   *string `json:"related_alert_id"`
	Suppressed       bool    `json:"suppressed"`
	BytesTransferred *int64  `json:"bytes_transferred"`
}

type netAnomalyStats struct {
	AnomaliesToday    int `json:"anomalies_today"`
	TrafficSpikes     int `json:"traffic_spikes"`
	SuspiciousPorts   int `json:"suspicious_ports"`
	C2BeaconingAlerts int `json:"c2_beaconing_alerts"`
}

// List returns all non-suppressed network anomalies.
// GET /api/v1/network-anomalies
func (h *NetworkAnomaliesHandler) List(c *gin.Context) {
	ctx := c.Request.Context()

	// First, try to derive from alerts
	if !h.tableExists(c) {
		// Derive from alerts where type/source suggests network anomaly
		rows, err := h.pool.Query(ctx, `
			SELECT id::text, COALESCE(source,''), COALESCE(agent_id::text,''),
			       title, severity, created_at
			FROM alerts
			WHERE (title ILIKE '%network%' OR title ILIKE '%traffic%' OR title ILIKE '%beaconing%'
			       OR title ILIKE '%lateral%' OR title ILIKE '%dns tunnel%')
			  AND status != 'closed'
			ORDER BY created_at DESC LIMIT 100
		`)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"anomalies": []interface{}{}})
			return
		}
		defer rows.Close()
		var anomalies []netAnomaly
		for rows.Next() {
			var a netAnomaly
			var ts time.Time
			var relatedID string
			if rows.Scan(&a.ID, &relatedID, &a.AgentID, &a.Description, &a.Severity, &ts) != nil {
				continue
			}
			a.RelatedAlertID = &relatedID
			a.Type = "traffic_spike"
			a.SourceIP = "unknown"
			a.DetectedAt = ts.Format(time.RFC3339)
			anomalies = append(anomalies, a)
		}
		if anomalies == nil {
			anomalies = []netAnomaly{}
		}
		c.JSON(http.StatusOK, gin.H{"anomalies": anomalies})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, type, agent_id, agent_hostname, description, severity,
		       source_ip, source_port, dest_ip, dest_port,
		       detected_at, related_alert_id, suppressed, bytes_transferred
		FROM network_anomalies
		WHERE suppressed = false
		ORDER BY detected_at DESC LIMIT 200
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"anomalies": []interface{}{}})
		return
	}
	defer rows.Close()

	var anomalies []netAnomaly
	for rows.Next() {
		var a netAnomaly
		var ts time.Time
		if rows.Scan(
			&a.ID, &a.Type, &a.AgentID, &a.AgentHostname, &a.Description, &a.Severity,
			&a.SourceIP, &a.SourcePort, &a.DestIP, &a.DestPort,
			&ts, &a.RelatedAlertID, &a.Suppressed, &a.BytesTransferred,
		) != nil {
			continue
		}
		a.DetectedAt = ts.Format(time.RFC3339)
		anomalies = append(anomalies, a)
	}
	if anomalies == nil {
		anomalies = []netAnomaly{}
	}
	c.JSON(http.StatusOK, gin.H{"anomalies": anomalies})
}

// GetStats returns aggregate network anomaly statistics.
// GET /api/v1/network-anomalies/stats
func (h *NetworkAnomaliesHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	stats := netAnomalyStats{}

	if h.tableExists(c) {
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM network_anomalies WHERE detected_at >= CURRENT_DATE`).Scan(&stats.AnomaliesToday)
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM network_anomalies WHERE type='traffic_spike' AND detected_at >= CURRENT_DATE`).Scan(&stats.TrafficSpikes)
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM network_anomalies WHERE type='new_port' AND detected_at >= CURRENT_DATE`).Scan(&stats.SuspiciousPorts)
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM network_anomalies WHERE type='beaconing' AND detected_at >= CURRENT_DATE`).Scan(&stats.C2BeaconingAlerts)
	} else {
		// Derive from alerts
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts
			 WHERE (title ILIKE '%network%' OR title ILIKE '%traffic%' OR title ILIKE '%beaconing%')
			 AND created_at >= CURRENT_DATE`).Scan(&stats.AnomaliesToday)
	}

	c.JSON(http.StatusOK, stats)
}

// Suppress marks a network anomaly as suppressed.
// POST /api/v1/network-anomalies/:id/suppress
func (h *NetworkAnomaliesHandler) Suppress(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	ctx := c.Request.Context()
	if h.tableExists(c) {
		_, _ = h.pool.Exec(ctx,
			`UPDATE network_anomalies SET suppressed=true WHERE id=$1`, id)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Anomaly suppressed"})
}
