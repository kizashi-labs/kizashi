package handlers

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// EscalationRuleHandler provides CRUD + toggle endpoints for alert escalation rules.
// Rules are evaluated by the escalation scheduler to notify on-call staff when
// high-severity alerts remain unresolved beyond a configured time threshold.
type EscalationRuleHandler struct {
	store *store.EscalationRuleStore
}

// NewEscalationRuleHandler creates a new EscalationRuleHandler.
func NewEscalationRuleHandler(s *store.EscalationRuleStore) *EscalationRuleHandler {
	return &EscalationRuleHandler{store: s}
}

// escalationRuleRequest is the shared request body for Create and Update.
type escalationRuleRequest struct {
	Name           string  `json:"name" binding:"required"`
	SeverityMin    int16   `json:"severity_min"`
	UnresolvedMins int     `json:"unresolved_mins"`
	EscalateTo     string  `json:"escalate_to"`
	NotifyChannel  *string `json:"notify_channel"`
	Enabled        bool    `json:"enabled"`
}

func validateEscalationRuleRequest(req *escalationRuleRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name は必須です"
	}
	if strings.TrimSpace(req.EscalateTo) == "" {
		return "escalate_to は必須です"
	}
	if req.SeverityMin < 1 || req.SeverityMin > 10 {
		return "severity_min は 1〜10 の範囲で指定してください"
	}
	if req.UnresolvedMins < 1 {
		return "unresolved_mins は 1 以上を指定してください"
	}
	return ""
}

// List returns all escalation rules.
// GET /api/v1/escalation-rules
func (h *EscalationRuleHandler) List(c *gin.Context) {
	rules, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エスカレーションルール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  rules,
		"total": len(rules),
	})
}

// Create inserts a new escalation rule (admin only).
// POST /api/v1/escalation-rules
func (h *EscalationRuleHandler) Create(c *gin.Context) {
	var req escalationRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Apply defaults if zero values were provided.
	if req.SeverityMin == 0 {
		req.SeverityMin = 5
	}
	if req.UnresolvedMins == 0 {
		req.UnresolvedMins = 60
	}
	if msg := validateEscalationRuleRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.CreateEscalationRuleInput{
		Name:           req.Name,
		SeverityMin:    req.SeverityMin,
		UnresolvedMins: req.UnresolvedMins,
		EscalateTo:     req.EscalateTo,
		NotifyChannel:  req.NotifyChannel,
		Enabled:        req.Enabled,
	}

	rule, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エスカレーションルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update replaces an existing escalation rule (admin only).
// PUT /api/v1/escalation-rules/:id
func (h *EscalationRuleHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req escalationRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SeverityMin == 0 {
		req.SeverityMin = 5
	}
	if req.UnresolvedMins == 0 {
		req.UnresolvedMins = 60
	}
	if msg := validateEscalationRuleRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.UpdateEscalationRuleInput{
		Name:           req.Name,
		SeverityMin:    req.SeverityMin,
		UnresolvedMins: req.UnresolvedMins,
		EscalateTo:     req.EscalateTo,
		NotifyChannel:  req.NotifyChannel,
		Enabled:        req.Enabled,
	}

	rule, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "エスカレーションルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エスカレーションルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes an escalation rule by ID (admin only).
// DELETE /api/v1/escalation-rules/:id
func (h *EscalationRuleHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "エスカレーションルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エスカレーションルールの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "エスカレーションルールを削除しました"})
}

// Toggle flips the enabled state of an escalation rule (admin only).
// PATCH /api/v1/escalation-rules/:id/toggle
func (h *EscalationRuleHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "エスカレーションルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エスカレーションルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}
