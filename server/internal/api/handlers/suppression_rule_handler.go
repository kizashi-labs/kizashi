package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/store"
)

// SuppressionRuleHandler provides CRUD endpoints for alert suppression rules.
type SuppressionRuleHandler struct {
	store *store.SuppressionRuleStore
}

// NewSuppressionRuleHandler creates a SuppressionRuleHandler.
func NewSuppressionRuleHandler(s *store.SuppressionRuleStore) *SuppressionRuleHandler {
	return &SuppressionRuleHandler{store: s}
}

// List handles GET /admin/suppression-rules
func (h *SuppressionRuleHandler) List(c *gin.Context) {
	rules, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "count": len(rules)})
}

// Get handles GET /admin/suppression-rules/:id
func (h *SuppressionRuleHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Get(c.Request.Context(), id)
	if err != nil || rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "抑制ルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Create handles POST /admin/suppression-rules
func (h *SuppressionRuleHandler) Create(c *gin.Context) {
	var r store.SuppressionRuleEntry
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}

	// Set created_by from context
	if userID, ok := c.Get("user_id"); ok {
		if uid, ok := userID.(string); ok && uid != "" {
			r.CreatedBy = &uid
		}
	}
	if r.MatchField == "" {
		r.MatchField = "title"
	}
	if r.SeverityMax == 0 {
		r.SeverityMax = 10
	}

	created, err := h.store.Create(c.Request.Context(), r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// Update handles PUT /admin/suppression-rules/:id
func (h *SuppressionRuleHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var r store.SuppressionRuleEntry
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}
	updated, err := h.store.Update(c.Request.Context(), id, r)
	if err != nil || updated == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// Delete handles DELETE /admin/suppression-rules/:id
func (h *SuppressionRuleHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// Toggle handles POST /admin/suppression-rules/:id/toggle
func (h *SuppressionRuleHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil || rule == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}
