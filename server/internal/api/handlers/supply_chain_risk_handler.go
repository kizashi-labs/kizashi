package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SupplyChainRiskHandler struct{ pool *pgxpool.Pool }

func NewSupplyChainRiskHandler(pool *pgxpool.Pool) *SupplyChainRiskHandler {
	return &SupplyChainRiskHandler{pool: pool}
}

func (h *SupplyChainRiskHandler) ListVendors(c *gin.Context) {
	vendors := []gin.H{
		{"id": uuid.New(), "name": "Microsoft Corporation", "vendor_type": "software", "risk_score": 3.2, "risk_level": "low", "criticality": "critical", "assessment_status": "completed", "last_assessed_at": time.Now().Add(-30 * 24 * time.Hour), "vulnerabilities": []gin.H{{"cve": "CVE-2024-21412", "severity": "high"}}},
		{"id": uuid.New(), "name": "Acme Cloud Services", "vendor_type": "cloud", "risk_score": 6.7, "risk_level": "high", "criticality": "high", "assessment_status": "in_progress", "last_assessed_at": time.Now().Add(-60 * 24 * time.Hour)},
		{"id": uuid.New(), "name": "OpenSSL Foundation", "vendor_type": "opensource", "risk_score": 4.1, "risk_level": "medium", "criticality": "critical", "assessment_status": "completed", "last_assessed_at": time.Now().Add(-15 * 24 * time.Hour)},
		{"id": uuid.New(), "name": "Third-Party Logger Inc.", "vendor_type": "software", "risk_score": 8.3, "risk_level": "critical", "criticality": "medium", "assessment_status": "overdue", "last_assessed_at": time.Now().Add(-180 * 24 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"vendors": vendors, "total": len(vendors)})
}

func (h *SupplyChainRiskHandler) GetVendor(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": "Acme Cloud Services", "vendor_type": "cloud",
		"risk_score": 6.7, "risk_level": "high", "criticality": "high",
		"sbom": gin.H{"components": 234, "known_vulnerabilities": 12, "outdated_components": 45},
		"vulnerabilities": []gin.H{
			{"cve": "CVE-2024-1234", "severity": "critical", "component": "log4j", "version": "2.14.0", "fixed_version": "2.17.1"},
			{"cve": "CVE-2023-5678", "severity": "high", "component": "openssl", "version": "1.0.2", "fixed_version": "3.0.0"},
		},
		"compliance_status": gin.H{"ISO27001": "compliant", "SOC2": "pending", "PCI-DSS": "non-compliant"},
	})
}

func (h *SupplyChainRiskHandler) CreateVendor(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["risk_score"] = 0.0
	req["risk_level"] = "low"
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *SupplyChainRiskHandler) AssessVendor(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var exists bool
	_ = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='supply_chain_vendors')`).Scan(&exists)
	if !exists {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "評価エンジンが利用できません"})
		return
	}

	var score float64
	err := h.pool.QueryRow(ctx, `SELECT risk_score FROM supply_chain_vendors WHERE id = $1`, id).Scan(&score)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ベンダーが見つかりません"})
		return
	}

	level := "low"
	if score > 7 {
		level = "critical"
	} else if score > 5 {
		level = "high"
	} else if score > 3 {
		level = "medium"
	}

	c.JSON(http.StatusOK, gin.H{
		"vendor_id":       id,
		"risk_score":      score,
		"risk_level":      level,
		"assessed_at":     time.Now().Format(time.RFC3339),
		"next_assessment": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		"findings_count":  0,
	})
}

func (h *SupplyChainRiskHandler) ListIncidents(c *gin.Context) {
	incidents := []gin.H{
		{"id": uuid.New(), "title": "SolarWinds型サプライチェーン攻撃の疑い", "severity": "critical", "status": "investigating", "vendor_name": "Third-Party Logger Inc.", "reported_at": time.Now().Add(-2 * 24 * time.Hour)},
		{"id": uuid.New(), "title": "依存ライブラリの脆弱性 (Log4Shell)", "severity": "high", "status": "resolved", "vendor_name": "Acme Cloud Services", "reported_at": time.Now().Add(-30 * 24 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"incidents": incidents, "total": len(incidents)})
}

func (h *SupplyChainRiskHandler) GetRiskMap(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_vendors": 47, "critical_risk": 3, "high_risk": 8, "medium_risk": 15, "low_risk": 21,
		"critical_vendors":    []string{"Third-Party Logger Inc.", "Legacy Connector Ltd.", "Unpatched SDK Co."},
		"recent_incidents":    2,
		"overdue_assessments": 7,
		"avg_risk_score":      4.2,
	})
}
