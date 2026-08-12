package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceStatusHandler manages NIST CSF + ISO 27001 control status data.
// Data is stored as JSON blobs in the system_settings table.
type ComplianceStatusHandler struct {
	Pool *pgxpool.Pool
}

func NewComplianceStatusHandler(pool *pgxpool.Pool) *ComplianceStatusHandler {
	return &ComplianceStatusHandler{Pool: pool}
}

const complianceStatusKey = "admin.compliance.status"

// GetStatus returns the stored NIST CSF + ISO 27001 compliance status.
// GET /api/v1/admin/compliance/status
func (h *ComplianceStatusHandler) GetStatus(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"error": "database not available"})
		return
	}

	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(),
		`SELECT value FROM system_settings WHERE key = $1`, complianceStatusKey,
	).Scan(&raw)
	if err != nil {
		// No record yet — return empty object so frontend uses its defaults
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	var result interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの解析に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// UpdateStatus persists the NIST CSF + ISO 27001 compliance status.
// PUT /api/v1/admin/compliance/status
func (h *ComplianceStatusHandler) UpdateStatus(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not available"})
		return
	}

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト形式です"})
		return
	}

	payload["last_assessed"] = time.Now().UTC().Format(time.RFC3339)

	raw, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの変換に失敗しました"})
		return
	}

	_, err = h.Pool.Exec(c.Request.Context(), `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE
		  SET value = EXCLUDED.value,
		      updated_at = NOW()`,
		complianceStatusKey, raw,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "last_assessed": payload["last_assessed"]})
}
