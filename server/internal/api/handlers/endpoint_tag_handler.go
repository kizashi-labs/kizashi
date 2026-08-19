package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EndpointTagHandler manages endpoint (agent) tags.
type EndpointTagHandler struct {
	pool *pgxpool.Pool
}

// NewEndpointTagHandler creates a new EndpointTagHandler.
func NewEndpointTagHandler(pool *pgxpool.Pool) *EndpointTagHandler {
	return &EndpointTagHandler{pool: pool}
}

type endpointTag struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Tag       string    `json:"tag"`
	Color     string    `json:"color"`
	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *EndpointTagHandler) ensureTable(ctx context.Context) error {
	_, err := h.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS endpoint_tags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  tag TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#6b7280',
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(agent_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_tags_agent ON endpoint_tags(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_tags_tag ON endpoint_tags(tag);
`)
	return err
}

// GetTags — GET /endpoints/:id/tags
func (h *EndpointTagHandler) GetTags(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	agentID := c.Param("id")
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, agent_id::TEXT, tag, color, created_by::TEXT, created_at
		 FROM endpoint_tags WHERE agent_id = $1 ORDER BY tag`, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var tags []endpointTag
	for rows.Next() {
		var t endpointTag
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Tag, &t.Color, &t.CreatedBy, &t.CreatedAt); err != nil {
			continue
		}
		tags = append(tags, t)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	if tags == nil {
		tags = []endpointTag{}
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// AddTag — POST /endpoints/:id/tags
func (h *EndpointTagHandler) AddTag(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	agentID := c.Param("id")
	var req struct {
		Tag   string `json:"tag" binding:"required"`
		Color string `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Color == "" {
		req.Color = "#6b7280"
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO endpoint_tags (agent_id, tag, color, created_by)
		 VALUES ($1::UUID, $2, $3, $4::UUID)
		 ON CONFLICT (agent_id, tag) DO UPDATE SET color = EXCLUDED.color
		 RETURNING id`,
		agentID, req.Tag, req.Color, nilIfEmpty(userID)).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タグの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "tag": req.Tag, "color": req.Color})
}

// RemoveTag — DELETE /endpoints/:id/tags/:tag
func (h *EndpointTagHandler) RemoveTag(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	agentID := c.Param("id")
	tag := c.Param("tag")

	tagExec, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM endpoint_tags WHERE agent_id = $1::UUID AND tag = $2`, agentID, tag)
	if err != nil || tagExec.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "タグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "タグを削除しました"})
}

// BulkAddTag — POST /endpoints/tags/bulk-add
func (h *EndpointTagHandler) BulkAddTag(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		AgentIDs []string `json:"agent_ids" binding:"required"`
		Tag      string   `json:"tag" binding:"required"`
		Color    string   `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Color == "" {
		req.Color = "#6b7280"
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)

	var added int
	for _, agentID := range req.AgentIDs {
		_, err := h.pool.Exec(c.Request.Context(),
			`INSERT INTO endpoint_tags (agent_id, tag, color, created_by)
			 VALUES ($1::UUID, $2, $3, $4::UUID)
			 ON CONFLICT (agent_id, tag) DO UPDATE SET color = EXCLUDED.color`,
			agentID, req.Tag, req.Color, nilIfEmpty(userID))
		if err == nil {
			added++
		}
	}
	c.JSON(http.StatusOK, gin.H{"added": added, "tag": req.Tag})
}

// BulkRemoveTag — POST /endpoints/tags/bulk-remove
func (h *EndpointTagHandler) BulkRemoveTag(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		AgentIDs []string `json:"agent_ids" binding:"required"`
		Tag      string   `json:"tag" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var removed int64
	for _, agentID := range req.AgentIDs {
		tag, err := h.pool.Exec(c.Request.Context(),
			`DELETE FROM endpoint_tags WHERE agent_id = $1::UUID AND tag = $2`, agentID, req.Tag)
		if err == nil {
			removed += tag.RowsAffected()
		}
	}
	c.JSON(http.StatusOK, gin.H{"removed": removed, "tag": req.Tag})
}

// ListAllTags — GET /endpoints/tags/all
func (h *EndpointTagHandler) ListAllTags(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT tag, color, COUNT(DISTINCT agent_id) AS agent_count
		 FROM endpoint_tags
		 GROUP BY tag, color
		 ORDER BY agent_count DESC, tag`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	type tagSummary struct {
		Tag        string `json:"tag"`
		Color      string `json:"color"`
		AgentCount int    `json:"agent_count"`
	}
	var result []tagSummary
	for rows.Next() {
		var ts tagSummary
		if err := rows.Scan(&ts.Tag, &ts.Color, &ts.AgentCount); err != nil {
			continue
		}
		result = append(result, ts)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	if result == nil {
		result = []tagSummary{}
	}
	c.JSON(http.StatusOK, gin.H{"tags": result})
}

// SearchByTag — GET /endpoints/tags/search?tag=X
func (h *EndpointTagHandler) SearchByTag(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	tag := c.Query("tag")
	if tag == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tagパラメーターが必要です"})
		return
	}

	// ORDER BY must name an expression that is in the select list when SELECT
	// DISTINCT is used, and et.agent_id (uuid) is not et.agent_id::TEXT — the
	// statement was rejected outright with 42P10, so filtering endpoints by tag
	// answered 500 every time.
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT DISTINCT et.agent_id::TEXT
		 FROM endpoint_tags et
		 WHERE et.tag = $1
		 ORDER BY et.agent_id::TEXT`, tag)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		agentIDs = append(agentIDs, id)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	if agentIDs == nil {
		agentIDs = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"agent_ids": agentIDs, "tag": tag})
}
