package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NTAHandler struct{ pool *pgxpool.Pool }

func NewNTAHandler(pool *pgxpool.Pool) *NTAHandler { return &NTAHandler{pool: pool} }

func (h *NTAHandler) ListRules(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "nta_rules")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT id, name, rule_type, protocol, severity, enabled, hit_count, false_positive_rate FROM nta_rules ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var rules []gin.H
	for rows.Next() {
		var id, name, ruleType, protocol, severity string
		var enabled bool
		var hitCount int
		var falsePositiveRate float64
		if err := rows.Scan(&id, &name, &ruleType, &protocol, &severity, &enabled, &hitCount, &falsePositiveRate); err != nil {
			continue
		}
		rules = append(rules, gin.H{
			"id":                  id,
			"name":                name,
			"rule_type":           ruleType,
			"protocol":            protocol,
			"severity":            severity,
			"enabled":             enabled,
			"hit_count":           hitCount,
			"false_positive_rate": falsePositiveRate,
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if rules == nil {
		rules = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func (h *NTAHandler) CreateRule(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["hit_count"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *NTAHandler) ListDetections(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "nta_detections")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"detections": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, threat_type, severity, confidence, status, detected_at FROM nta_detections ORDER BY detected_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var detections []gin.H
	for rows.Next() {
		var id, srcIP, dstIP, protocol, threatType, severity, status string
		var srcPort, dstPort int
		var confidence float64
		var detectedAt time.Time
		if err := rows.Scan(&id, &srcIP, &dstIP, &srcPort, &dstPort, &protocol, &threatType, &severity, &confidence, &status, &detectedAt); err != nil {
			continue
		}
		detections = append(detections, gin.H{
			"id":          id,
			"src_ip":      srcIP,
			"dst_ip":      dstIP,
			"src_port":    srcPort,
			"dst_port":    dstPort,
			"protocol":    protocol,
			"threat_type": threatType,
			"severity":    severity,
			"confidence":  confidence,
			"status":      status,
			"detected_at": detectedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if detections == nil {
		detections = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"detections": detections, "total": len(detections)})
}

func (h *NTAHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	detectionsExists := tableIsThere(ctx, h.pool, "nta_detections")
	rulesExists := tableIsThere(ctx, h.pool, "nta_rules")

	var activeRules, detectionsToday, critical, high, medium, low int
	if rulesExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_rules WHERE enabled = true`).Scan(&activeRules)) {
			return
		}
	}
	if detectionsExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE detected_at >= CURRENT_DATE`).Scan(&detectionsToday)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE severity = 'critical'`).Scan(&critical)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE severity = 'high'`).Scan(&high)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE severity = 'medium'`).Scan(&medium)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM nta_detections WHERE severity = 'low'`).Scan(&low)) {
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"active_rules":                 activeRules,
		"detections_today":             detectionsToday,
		"critical":                     critical,
		"high":                         high,
		"medium":                       medium,
		"low":                          low,
		"top_threats":                  []gin.H{},
		"network_flows_analyzed_today": 0,
		"avg_detection_latency_ms":     0,
	})
}

func (h *NTAHandler) GetFlowAnalysis(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"top_talkers": []gin.H{
			{"ip": "10.0.1.45", "hostname": "WS-045", "bytes_sent": int64(2.3e9), "bytes_received": int64(890e6), "connections": 1234},
			{"ip": "10.0.2.12", "hostname": "SERVER-012", "bytes_sent": int64(890e6), "bytes_received": int64(12.1e9), "connections": 8923},
		},
		"protocol_distribution": []gin.H{
			{"protocol": "HTTPS", "bytes": int64(45.2e9), "percentage": 62.3},
			{"protocol": "HTTP", "bytes": int64(8.9e9), "percentage": 12.2},
			{"protocol": "SMB", "bytes": int64(6.2e9), "percentage": 8.5},
			{"protocol": "DNS", "bytes": int64(1.2e9), "percentage": 1.7},
		},
	})
}
