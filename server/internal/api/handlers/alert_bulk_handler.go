package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
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

// Two of these four endpoints used to answer 200 {"updated": 0, "note": ...}
// when their statement failed, on the theory that a missing or differently
// typed column is not the caller's problem. It made them permanently and
// invisibly inert:
//
//	bulk-tag     UPDATE alerts SET tags ...  -> 42703 column "tags" does not exist
//	bulk-assign  UPDATE alerts SET assigned_to=$1 -> 23503 when the user is unknown
//
// The console checks the HTTP status and nothing else, so it reported
// 「N件にタグを追加しました」 over a request that stored nothing. A caller that
// is told the work succeeded cannot retry, cannot escalate, and has no reason
// to look. Failures are now reported as failures; the missing column is created
// by migration 374.
//
// bulkErrorStatus maps the two faults a caller can actually cause onto 4xx and
// leaves everything else a 500.
func bulkErrorStatus(err error) (int, string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "22P02": // invalid_text_representation — an id that is not a uuid
			return http.StatusBadRequest, "IDの形式が正しくありません"
		case "23503": // foreign_key_violation — assignee is not a known user
			return http.StatusBadRequest, "指定されたユーザーが存在しません"
		}
	}
	return http.StatusInternalServerError, "一括操作に失敗しました"
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
		`UPDATE alerts SET status=$1, updated_at=NOW() WHERE id = ANY($2::uuid[])`,
		req.Status, req.IDs)
	if err != nil {
		slog.Error("アラート一括ステータス更新失敗", "error", err)
		status, msg := bulkErrorStatus(err)
		c.JSON(status, gin.H{"error": msg})
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
	result, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM alerts WHERE id = ANY($1::uuid[])`, req.IDs)
	if err != nil {
		slog.Error("アラート一括削除失敗", "error", err)
		status, msg := bulkErrorStatus(err)
		c.JSON(status, gin.H{"error": msg})
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
	tag := strings.TrimSpace(req.Tag)
	if len(req.IDs) == 0 || tag == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idsとtagは必須です"})
		return
	}
	// Adding a tag an alert already carries is a no-op rather than a second copy
	// in the array. Bulk actions are run over overlapping selections routinely,
	// and `tags || jsonb_build_array($1)` would otherwise accumulate duplicates
	// that no reader deduplicates.
	//
	// The row is still counted as updated in that case: the caller asked for
	// these alerts to carry the tag, and afterwards they do. Reporting 0 for a
	// repeat would read as a failure.
	result, err := h.pool.Exec(c.Request.Context(),
		`UPDATE alerts
		    SET tags = CASE WHEN COALESCE(tags, '[]'::jsonb) ? $1 THEN tags
		                    ELSE COALESCE(tags, '[]'::jsonb) || jsonb_build_array($1::text) END,
		        updated_at = NOW()
		  WHERE id = ANY($2::uuid[])`,
		tag, req.IDs)
	if err != nil {
		slog.Error("アラート一括タグ付け失敗", "error", err)
		status, msg := bulkErrorStatus(err)
		c.JSON(status, gin.H{"error": msg})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": result.RowsAffected(), "tag": tag})
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
		`UPDATE alerts SET assigned_to=$1::uuid, updated_at=NOW() WHERE id = ANY($2::uuid[])`,
		req.UserID, req.IDs)
	if err != nil {
		slog.Error("アラート一括アサイン失敗", "error", err)
		status, msg := bulkErrorStatus(err)
		c.JSON(status, gin.H{"error": msg})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": result.RowsAffected(), "assigned_to": req.UserID})
}
