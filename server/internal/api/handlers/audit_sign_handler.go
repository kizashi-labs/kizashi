package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditSignHandler provides endpoints for digitally signed audit log exports.
type AuditSignHandler struct {
	pool      *pgxpool.Pool
	jwtSecret string
}

// NewAuditSignHandler creates an AuditSignHandler.
func NewAuditSignHandler(pool *pgxpool.Pool, jwtSecret string) *AuditSignHandler {
	return &AuditSignHandler{pool: pool, jwtSecret: jwtSecret}
}

type auditSignRecord struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Action     string    `json:"action"`
	ResourceID string    `json:"resource_id"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
}

func (h *AuditSignHandler) computeHMAC(data []byte) string {
	key := []byte(h.jwtSecret + "audit-export-v1")
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *AuditSignHandler) auditTableExists(c *gin.Context) bool {
	var exists bool
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='audit_logs')`).
		Scan(&exists); err != nil {
		slog.Warn("audit_sign: audit_logs テーブル確認に失敗しました", "error", err)
	}
	return exists
}

// ExportSigned handles GET /admin/audit/signed-export
func (h *AuditSignHandler) ExportSigned(c *gin.Context) {
	fromStr := c.DefaultQuery("from", "")
	toStr := c.DefaultQuery("to", "")
	limitStr := c.DefaultQuery("limit", "1000")

	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now

	var err error
	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "fromパラメータが無効です"})
			return
		}
	}
	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "toパラメータが無効です"})
			return
		}
	}

	limit := 1000
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if limit > 5000 {
		limit = 5000
	}

	if !h.auditTableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"exported_at":  now,
			"record_count": 0,
			"from":         from,
			"to":           to,
			"records":      []interface{}{},
			"signature":    h.computeHMAC([]byte("[]")),
			"algorithm":    "HMAC-SHA256",
		})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT COALESCE(id,''), COALESCE(user_id,''), COALESCE(action,''),
		       COALESCE(resource_id,''), COALESCE(ip_address,''), timestamp
		FROM audit_logs
		WHERE timestamp BETWEEN $1 AND $2
		ORDER BY timestamp
		LIMIT $3`,
		from, to, limit,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "監査ログの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var records []auditSignRecord
	for rows.Next() {
		var r auditSignRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.Action,
			&r.ResourceID, &r.IPAddress, &r.CreatedAt); err != nil {
			continue
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if records == nil {
		records = []auditSignRecord{}
	}

	recordsJSON, err := json.Marshal(records)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JSONのシリアライズに失敗しました"})
		return
	}

	signature := h.computeHMAC(recordsJSON)
	timestamp := now.Format("20060102_150405")

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-export-%s.json"`, timestamp))
	c.Header("Content-Type", "application/json; charset=utf-8")

	c.JSON(http.StatusOK, gin.H{
		"exported_at":  now,
		"record_count": len(records),
		"from":         from,
		"to":           to,
		"records":      records,
		"signature":    signature,
		"algorithm":    "HMAC-SHA256",
	})
}

// VerifySignature handles POST /admin/audit/verify-signature
func (h *AuditSignHandler) VerifySignature(c *gin.Context) {
	var body struct {
		Records   json.RawMessage `json:"records"`
		Signature string          `json:"signature" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です"})
		return
	}

	if body.Records == nil || body.Signature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "recordsとsignatureは必須です"})
		return
	}

	expected := h.computeHMAC(body.Records)
	valid := hmac.Equal([]byte(expected), []byte(body.Signature))

	msg := "署名が有効です"
	if !valid {
		msg = "署名が無効です"
	}
	c.JSON(http.StatusOK, gin.H{
		"valid":   valid,
		"message": msg,
	})
}
