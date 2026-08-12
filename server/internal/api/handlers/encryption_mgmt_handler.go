package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EncryptionMgmtHandler struct{ pool *pgxpool.Pool }

func NewEncryptionMgmtHandler(pool *pgxpool.Pool) *EncryptionMgmtHandler {
	return &EncryptionMgmtHandler{pool: pool}
}

func (h *EncryptionMgmtHandler) ListPolicies(c *gin.Context) {
	policies := []gin.H{
		{"id": uuid.New(), "name": "フルディスク暗号化 - 全エンドポイント", "encryption_type": "full_disk", "algorithm": "AES-256", "enforcement_mode": "enforce", "enabled": true, "covered_endpoints": 210, "compliance_rate": 96.2},
		{"id": uuid.New(), "name": "リムーバブルメディア暗号化", "encryption_type": "removable", "algorithm": "AES-256", "enforcement_mode": "enforce", "enabled": true, "covered_endpoints": 210, "compliance_rate": 89.5},
		{"id": uuid.New(), "name": "機密フォルダ暗号化", "encryption_type": "folder", "algorithm": "AES-256", "enforcement_mode": "monitor", "enabled": true, "covered_endpoints": 45, "compliance_rate": 100.0},
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

func (h *EncryptionMgmtHandler) CreatePolicy(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["covered_endpoints"] = 0
	req["compliance_rate"] = 0.0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

// ListEndpointStatus returns per-endpoint disk-encryption status from the real
// endpoint_encryption table (populated by the agent encryption reporter). Agents
// that have never reported appear as "unknown".
func (h *EncryptionMgmtHandler) ListEndpointStatus(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT ag.id::text, ag.hostname, COALESCE(ag.os_type,''),
		       e.encrypted, COALESCE(e.method,''), COALESCE(e.details,''), e.reported_at
		FROM agents ag
		LEFT JOIN endpoint_encryption e ON e.agent_id = ag.id
		ORDER BY ag.hostname`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"endpoints": []any{}, "total": 0})
		return
	}
	defer rows.Close()

	statuses := []gin.H{}
	for rows.Next() {
		var id, hostname, osType, method, details string
		var encrypted *bool
		var reportedAt *time.Time
		if err := rows.Scan(&id, &hostname, &osType, &encrypted, &method, &details, &reportedAt); err != nil {
			continue
		}
		status := "unknown"
		compliance := "unknown"
		if encrypted != nil {
			if *encrypted {
				status, compliance = "encrypted", "compliant"
			} else {
				status, compliance = "unencrypted", "non-compliant"
			}
		}
		entry := gin.H{
			"endpoint_id":       id,
			"hostname":          hostname,
			"os_type":           osType,
			"status":            status,
			"algorithm":         method,
			"details":           details,
			"compliance_status": compliance,
		}
		if reportedAt != nil {
			entry["last_verified_at"] = reportedAt.UTC().Format(time.RFC3339)
		}
		statuses = append(statuses, entry)
	}
	c.JSON(http.StatusOK, gin.H{"endpoints": statuses, "total": len(statuses)})
}

// GetStats returns fleet-wide encryption coverage from endpoint_encryption.
func (h *EncryptionMgmtHandler) GetStats(c *gin.Context) {
	var total, encrypted, unencrypted, unknown int
	_ = h.pool.QueryRow(c.Request.Context(), `
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE e.encrypted IS TRUE),
		  COUNT(*) FILTER (WHERE e.encrypted IS FALSE),
		  COUNT(*) FILTER (WHERE e.encrypted IS NULL)
		FROM agents ag
		LEFT JOIN endpoint_encryption e ON e.agent_id = ag.id
	`).Scan(&total, &encrypted, &unencrypted, &unknown)

	rate := 0.0
	if total > 0 {
		rate = float64(encrypted) / float64(total) * 100
	}
	c.JSON(http.StatusOK, gin.H{
		"total_endpoints":         total,
		"encrypted":               encrypted,
		"unencrypted":             unencrypted,
		"unknown":                 unknown,
		"overall_compliance_rate": rate,
	})
}
