package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/suppression"
	"github.com/gin-gonic/gin"
)

// SuppressionEngineHandler wraps the suppression.Engine for HTTP management.
type SuppressionEngineHandler struct {
	engine *suppression.Engine
}

// NewSuppressionEngineHandler creates a handler backed by the given engine.
func NewSuppressionEngineHandler(engine *suppression.Engine) *SuppressionEngineHandler {
	return &SuppressionEngineHandler{engine: engine}
}

type createSuppressionRuleRequest struct {
	Name        string                  `json:"name" binding:"required"`
	Description string                  `json:"description"`
	Enabled     *bool                   `json:"enabled"`
	Conditions  []suppression.Condition `json:"conditions"`
	Duration    int64                   `json:"duration_seconds"`
}

// ListRules handles GET /api/v1/admin/suppression/rules
func (h *SuppressionEngineHandler) ListRules(c *gin.Context) {
	rules := h.engine.GetRules()
	stats := h.engine.GetStats()

	type ruleResp struct {
		ID          string                  `json:"id"`
		Name        string                  `json:"name"`
		Description string                  `json:"description"`
		Enabled     bool                    `json:"enabled"`
		Conditions  []suppression.Condition `json:"conditions"`
		HitCount    int64                   `json:"hit_count"`
	}
	out := make([]ruleResp, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleResp{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Enabled:     r.Enabled,
			Conditions:  r.Conditions,
			HitCount:    r.HitCount,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"rules": out,
		"stats": stats,
	})
}

// CreateRule handles POST /api/v1/admin/suppression/rules
func (h *SuppressionEngineHandler) CreateRule(c *gin.Context) {
	var req createSuppressionRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &suppression.SuppressionRule{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     enabled,
		Conditions:  req.Conditions,
	}
	if req.Duration > 0 {
		rule.Duration = asDuration(req.Duration)
	}

	if err := h.engine.AddRule(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// UpdateRule handles PUT /api/v1/admin/suppression/rules/:id
func (h *SuppressionEngineHandler) UpdateRule(c *gin.Context) {
	id := c.Param("id")
	var req createSuppressionRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	updated := &suppression.SuppressionRule{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     enabled,
		Conditions:  req.Conditions,
	}
	if req.Duration > 0 {
		updated.Duration = asDuration(req.Duration)
	}

	if err := h.engine.UpdateRule(id, updated); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// DeleteRule handles DELETE /api/v1/admin/suppression/rules/:id
func (h *SuppressionEngineHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if err := h.engine.DeleteRule(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// ToggleRule handles PUT /api/v1/admin/suppression/rules/:id/toggle
func (h *SuppressionEngineHandler) ToggleRule(c *gin.Context) {
	id := c.Param("id")
	rules := h.engine.GetRules()
	for _, r := range rules {
		if r.ID == id {
			r.Enabled = !r.Enabled
			updated := &suppression.SuppressionRule{
				Name:        r.Name,
				Description: r.Description,
				Enabled:     r.Enabled,
				Conditions:  r.Conditions,
				Duration:    r.Duration,
				ExpiresAt:   r.ExpiresAt,
			}
			if err := h.engine.UpdateRule(id, updated); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
				return
			}
			c.JSON(http.StatusOK, gin.H{"enabled": r.Enabled})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
}

// TestAlert handles POST /api/v1/admin/suppression/test
func (h *SuppressionEngineHandler) TestAlert(c *gin.Context) {
	var req struct {
		Alert map[string]interface{} `json:"alert"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Alert == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must contain {alert: {...}}"})
		return
	}
	suppressed, ruleName := h.engine.ShouldSuppress(req.Alert)
	c.JSON(http.StatusOK, gin.H{
		"suppressed": suppressed,
		"rule":       ruleName,
	})
}

// GetStats handles GET /api/v1/admin/suppression/stats
func (h *SuppressionEngineHandler) GetStats(c *gin.Context) {
	stats := h.engine.GetStats()
	c.JSON(http.StatusOK, stats)
}

// asDuration converts int64 seconds to time.Duration.
func asDuration(s int64) time.Duration {
	return time.Duration(s) * time.Second
}

// secondsToDuration converts int64 seconds to time.Duration.
func secondsToDuration(s int64) time.Duration {
	return time.Duration(s) * time.Second
}
