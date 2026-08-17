package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ZTNAHandler struct{ pool *pgxpool.Pool }

func NewZTNAHandler(pool *pgxpool.Pool) *ZTNAHandler { return &ZTNAHandler{pool: pool} }

func (h *ZTNAHandler) ListPolicies(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "ztna_policies")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"policies": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT id, name, policy_type, enforcement_mode, enabled, priority, hit_count, last_triggered_at FROM ztna_policies ORDER BY priority ASC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var policies []gin.H
	for rows.Next() {
		var id, name, policyType, enforcementMode string
		var enabled bool
		var priority, hitCount int
		var lastTriggeredAt *time.Time
		if err := rows.Scan(&id, &name, &policyType, &enforcementMode, &enabled, &priority, &hitCount, &lastTriggeredAt); err != nil {
			continue
		}
		p := gin.H{
			"id":               id,
			"name":             name,
			"policy_type":      policyType,
			"enforcement_mode": enforcementMode,
			"enabled":          enabled,
			"priority":         priority,
			"hit_count":        hitCount,
		}
		if lastTriggeredAt != nil {
			p["last_triggered_at"] = lastTriggeredAt.Format(time.RFC3339)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if policies == nil {
		policies = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

func (h *ZTNAHandler) CreatePolicy(c *gin.Context) {
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

func (h *ZTNAHandler) GetAccessLogs(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "ztna_access_logs")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"logs": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT id, user_id, device_id, source_ip, resource, decision, risk_score, timestamp FROM ztna_access_logs ORDER BY timestamp DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var logs []gin.H
	for rows.Next() {
		var id, userID, deviceID, sourceIP, resource, decision string
		var riskScore float64
		var ts time.Time
		if err := rows.Scan(&id, &userID, &deviceID, &sourceIP, &resource, &decision, &riskScore, &ts); err != nil {
			continue
		}
		logs = append(logs, gin.H{
			"id":         id,
			"user_id":    userID,
			"device_id":  deviceID,
			"source_ip":  sourceIP,
			"resource":   resource,
			"decision":   decision,
			"risk_score": riskScore,
			"timestamp":  ts.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if logs == nil {
		logs = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs, "total": len(logs)})
}

func (h *ZTNAHandler) GetDevicePosture(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "ztna_device_posture")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"devices": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT device_id, hostname, os_type, os_version, compliance_score, status, last_checked_at FROM ztna_device_posture ORDER BY last_checked_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var devices []gin.H
	for rows.Next() {
		var deviceID, hostname, osType, osVersion, status string
		var complianceScore float64
		var lastCheckedAt time.Time
		if err := rows.Scan(&deviceID, &hostname, &osType, &osVersion, &complianceScore, &status, &lastCheckedAt); err != nil {
			continue
		}
		devices = append(devices, gin.H{
			"device_id":        deviceID,
			"hostname":         hostname,
			"os_type":          osType,
			"os_version":       osVersion,
			"compliance_score": complianceScore,
			"status":           status,
			"last_checked_at":  lastCheckedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if devices == nil {
		devices = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices, "total": len(devices)})
}

func (h *ZTNAHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	policiesExists := tableIsThere(ctx, h.pool, "ztna_policies")
	logsExists := tableIsThere(ctx, h.pool, "ztna_access_logs")
	postureExists := tableIsThere(ctx, h.pool, "ztna_device_posture")

	var activePolicies, totalToday, allowed, denied, challenged int
	var avgRiskScore float64
	var compliantDevices, nonCompliantDevices int

	if policiesExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_policies WHERE enabled = true`).Scan(&activePolicies)) {
			return
		}
	}
	if logsExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_access_logs WHERE DATE(timestamp) = CURRENT_DATE`).Scan(&totalToday)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_access_logs WHERE decision = 'allow' AND DATE(timestamp) = CURRENT_DATE`).Scan(&allowed)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_access_logs WHERE decision = 'deny' AND DATE(timestamp) = CURRENT_DATE`).Scan(&denied)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_access_logs WHERE decision = 'challenge' AND DATE(timestamp) = CURRENT_DATE`).Scan(&challenged)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COALESCE(AVG(risk_score), 0) FROM ztna_access_logs WHERE DATE(timestamp) = CURRENT_DATE`).Scan(&avgRiskScore)) {
			return
		}
	}
	if postureExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_device_posture WHERE status = 'compliant'`).Scan(&compliantDevices)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztna_device_posture WHERE status = 'non-compliant'`).Scan(&nonCompliantDevices)) {
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"active_policies":           activePolicies,
		"total_access_events_today": totalToday,
		"allowed":                   allowed,
		"denied":                    denied,
		"challenged":                challenged,
		"compliant_devices":         compliantDevices,
		"non_compliant_devices":     nonCompliantDevices,
		"avg_risk_score":            avgRiskScore,
		"top_denied_resources":      []string{},
	})
}
