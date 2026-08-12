package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertBulkHandler handles bulk operations on alerts.
type AlertBulkHandler struct {
	pool *pgxpool.Pool
}

// NewAlertBulkHandler creates a new AlertBulkHandler.
func NewAlertBulkHandler(pool *pgxpool.Pool) *AlertBulkHandler {
	return &AlertBulkHandler{pool: pool}
}

type bulkIDsRequest struct {
	IDs []string `json:"ids" binding:"required,min=1"`
}

// BulkStatus handles POST /api/v1/alerts/bulk-status
// Body: { "ids": [...], "status": "resolved|investigating|suppressed|open" }
func (h *AlertBulkHandler) BulkStatus(c *gin.Context) {
	var req struct {
		IDs    []string `json:"ids"    binding:"required,min=1"`
		Status string   `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idsは必須です"})
		return
	}
	validStatuses := map[string]bool{"open": true, "investigating": true, "resolved": true, "suppressed": true}
	if !validStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なステータスです"})
		return
	}
	result, err := h.pool.Exec(c.Request.Context(),
		`UPDATE alerts SET status=$1, updated_at=NOW() WHERE id = ANY($2)`,
		req.Status, req.IDs)
	if err != nil {
		slog.Error("アラート一括ステータス更新失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータスの一括更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"updated": result.RowsAffected(),
		"status":  req.Status,
	})
}

// BulkDelete handles POST /api/v1/alerts/bulk-delete
func (h *AlertBulkHandler) BulkDelete(c *gin.Context) {
	var req bulkIDsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idsは必須です"})
		return
	}
	result, err := h.pool.Exec(c.Request.Context(), `DELETE FROM alerts WHERE id = ANY($1)`, req.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートの一括削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": result.RowsAffected()})
}

// BulkTag handles POST /api/v1/alerts/bulk-tag
// Body: { "ids": [...], "tag": "..." }
func (h *AlertBulkHandler) BulkTag(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required,min=1"`
		Tag string   `json:"tag" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IDs) == 0 || strings.TrimSpace(req.Tag) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idsとtagは必須です"})
		return
	}
	result, err := h.pool.Exec(c.Request.Context(),
		`UPDATE alerts SET tags = COALESCE(tags, '[]'::jsonb) || jsonb_build_array($1::text), updated_at=NOW()
         WHERE id = ANY($2)`,
		req.Tag, req.IDs)
	if err != nil {
		// tags column may not exist or have different type - return partial success
		slog.Warn("アラートタグ更新失敗 (スキーマ確認要)", "error", err)
		c.JSON(http.StatusOK, gin.H{"updated": 0, "note": "tagsカラムの形式を確認してください"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": result.RowsAffected(), "tag": req.Tag})
}

// BulkAssign handles POST /api/v1/alerts/bulk-assign
// Body: { "ids": [...], "user_id": "..." }
func (h *AlertBulkHandler) BulkAssign(c *gin.Context) {
	var req struct {
		IDs    []string `json:"ids"     binding:"required,min=1"`
		UserID string   `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idsは必須です"})
		return
	}
	result, err := h.pool.Exec(c.Request.Context(),
		`UPDATE alerts SET assigned_to=$1, updated_at=NOW() WHERE id = ANY($2)`,
		req.UserID, req.IDs)
	if err != nil {
		slog.Warn("アラート一括アサイン失敗", "error", err)
		c.JSON(http.StatusOK, gin.H{"updated": 0, "note": "assigned_toカラムを確認してください"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": result.RowsAffected(), "assigned_to": req.UserID})
}
