package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertActionHandler handles per-alert action endpoints.
type AlertActionHandler struct {
	pool *pgxpool.Pool
}

// NewAlertActionHandler creates a new AlertActionHandler.
func NewAlertActionHandler(pool *pgxpool.Pool) *AlertActionHandler {
	return &AlertActionHandler{pool: pool}
}

var validAlertStatuses = map[string]bool{
	"open": true, "investigating": true, "resolved": true, "suppressed": true,
}

// isValidAlertStatus reports whether s is an accepted alert status value.
func isValidAlertStatus(s string) bool { return validAlertStatuses[s] }

// UpdateStatus handles POST /api/v1/alerts/:id/status
func (h *AlertActionHandler) UpdateStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !isValidAlertStatus(req.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なステータスです"})
		return
	}
	result, err := h.pool.Exec(c.Request.Context(),
		`UPDATE alerts SET status=$1, updated_at=NOW() WHERE id=$2`, req.Status, id)
	if err != nil || result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "アラートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": req.Status})
}

// Enrich handles POST /api/v1/alerts/:id/enrich
// Triggers async VT enrichment for the alert.
func (h *AlertActionHandler) Enrich(c *gin.Context) {
	id := c.Param("id")
	// Verify alert exists
	var title string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT title FROM alerts WHERE id=$1`, id).Scan(&title)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アラートが見つかりません"})
		return
	}
	// Trigger enrichment asynchronously (update enrichment JSONB with pending status)
	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE alerts SET enrichment = jsonb_set(COALESCE(enrichment, '{}'), '{status}', '"pending"'), updated_at=NOW() WHERE id=$1`,
		id)
	if err != nil {
		slog.Warn("VTエンリッチメント開始失敗", "error", err, "id", id)
	}
	c.JSON(http.StatusAccepted, gin.H{
		"message": "VT解析リクエストを受け付けました",
		"id":      id,
		"status":  "pending",
		"note":    "VIRUSTOTAL_API_KEYが設定されている場合、バックグラウンドで処理されます",
	})
}
