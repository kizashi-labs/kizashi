package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskActionRule mirrors the risk_action_rules table row.
type RiskActionRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Threshold int       `json:"threshold"`
	Action    string    `json:"action"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RiskActionHandler provides CRUD endpoints for risk_action_rules.
type RiskActionHandler struct {
	Pool *pgxpool.Pool
}

// NewRiskActionHandler creates a new RiskActionHandler.
func NewRiskActionHandler(pool *pgxpool.Pool) *RiskActionHandler {
	return &RiskActionHandler{Pool: pool}
}

// List returns all risk action rules.
// GET /api/v1/risk-actions
func (h *RiskActionHandler) List(c *gin.Context) {
	rows, err := h.Pool.Query(c.Request.Context(),
		`SELECT id::text, name, threshold, action, enabled, created_at, updated_at
		 FROM risk_action_rules
		 ORDER BY created_at ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リスクアクションルール一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var rules []RiskActionRule
	for rows.Next() {
		var r RiskActionRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Threshold, &r.Action, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if rules == nil {
		rules = []RiskActionRule{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

// Create adds a new risk action rule.
// POST /api/v1/risk-actions
func (h *RiskActionHandler) Create(c *gin.Context) {
	var req struct {
		Name      string `json:"name"      binding:"required"`
		Threshold int    `json:"threshold" binding:"required,min=1,max=100"`
		Action    string `json:"action"`
		Enabled   bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name と threshold (1-100) は必須です"})
		return
	}
	if req.Action == "" {
		req.Action = "isolate"
	}
	if req.Action != "isolate" && req.Action != "alert_only" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action は 'isolate' または 'alert_only' です"})
		return
	}

	var rule RiskActionRule
	err := h.Pool.QueryRow(c.Request.Context(), `
		INSERT INTO risk_action_rules (name, threshold, action, enabled)
		VALUES ($1, $2, $3, $4)
		RETURNING id::text, name, threshold, action, enabled, created_at, updated_at`,
		req.Name, req.Threshold, req.Action, req.Enabled,
	).Scan(&rule.ID, &rule.Name, &rule.Threshold, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リスクアクションルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update replaces a risk action rule.
// PUT /api/v1/risk-actions/:id
func (h *RiskActionHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name      string `json:"name"      binding:"required"`
		Threshold int    `json:"threshold" binding:"required,min=1,max=100"`
		Action    string `json:"action"`
		Enabled   bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name と threshold (1-100) は必須です"})
		return
	}
	if req.Action == "" {
		req.Action = "isolate"
	}
	if req.Action != "isolate" && req.Action != "alert_only" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action は 'isolate' または 'alert_only' です"})
		return
	}

	var rule RiskActionRule
	err := h.Pool.QueryRow(c.Request.Context(), `
		UPDATE risk_action_rules
		SET name = $2, threshold = $3, action = $4, enabled = $5, updated_at = NOW()
		WHERE id = $1::uuid
		RETURNING id::text, name, threshold, action, enabled, created_at, updated_at`,
		id, req.Name, req.Threshold, req.Action, req.Enabled,
	).Scan(&rule.ID, &rule.Name, &rule.Threshold, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "リスクアクションルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes a risk action rule.
// DELETE /api/v1/risk-actions/:id
func (h *RiskActionHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.Pool.Exec(c.Request.Context(),
		`DELETE FROM risk_action_rules WHERE id = $1::uuid`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "リスクアクションルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "リスクアクションルールを削除しました", "id": id})
}

// Toggle enables or disables a risk action rule.
// PATCH /api/v1/risk-actions/:id/toggle
func (h *RiskActionHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	tag, err := h.Pool.Exec(c.Request.Context(), `
		UPDATE risk_action_rules SET enabled = $2, updated_at = NOW() WHERE id = $1::uuid`,
		id, req.Enabled,
	)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "リスクアクションルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "リスクアクションルールを更新しました", "id": id, "enabled": req.Enabled})
}
