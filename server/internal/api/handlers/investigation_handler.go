package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/investigation"
	"github.com/gin-gonic/gin"
)

// InvestigationHandler exposes HTTP endpoints for AI-powered alert investigation.
type InvestigationHandler struct {
	inv *investigation.Investigator
}

// NewInvestigationHandler creates a new InvestigationHandler.
// If inv is nil or has no API key configured the handler returns graceful
// "not available" responses instead of errors.
func NewInvestigationHandler(inv *investigation.Investigator) *InvestigationHandler {
	return &InvestigationHandler{inv: inv}
}

// investigationResponse is the JSON shape returned by both endpoints.
type investigationResponse struct {
	AlertID        string    `json:"alert_id"`
	Summary        string    `json:"summary"`
	Model          string    `json:"model,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	InvestigatedAt time.Time `json:"investigated_at,omitempty"`
	Available      bool      `json:"available"`
}

// GetInvestigation returns the stored AI investigation summary for an alert.
//
//	GET /api/v1/alerts/:id/investigation
func (h *InvestigationHandler) GetInvestigation(c *gin.Context) {
	if h.inv == nil || !h.inv.IsConfigured() {
		c.JSON(http.StatusOK, investigationResponse{
			AlertID:   c.Param("id"),
			Available: false,
			Summary:   "AI investigation is not configured on this server.",
		})
		return
	}

	alertID := c.Param("id")
	ctx := c.Request.Context()

	// Read persisted columns directly so we avoid a second LLM call.
	var summary, model *string
	var investigatedAt *time.Time

	err := h.inv.DB().QueryRow(ctx, `
		SELECT ai_summary, ai_model, ai_investigated_at
		FROM   alerts
		WHERE  id = $1`, alertID,
	).Scan(&summary, &model, &investigatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アラートが見つかりません"})
		return
	}

	if summary == nil || *summary == "" {
		c.JSON(http.StatusOK, investigationResponse{
			AlertID:   alertID,
			Available: false,
			Summary:   "This alert has not been investigated yet. Use POST /investigate to trigger one.",
		})
		return
	}

	resp := investigationResponse{
		AlertID:   alertID,
		Summary:   *summary,
		Available: true,
	}
	if model != nil {
		resp.Model = *model
	}
	if investigatedAt != nil {
		resp.InvestigatedAt = *investigatedAt
	}
	c.JSON(http.StatusOK, resp)
}

// GetMode returns the current AI investigation mode settings.
//
//	GET /api/v1/admin/ai-investigation/mode
func (h *InvestigationHandler) GetMode(c *gin.Context) {
	if h.inv == nil {
		c.JSON(http.StatusOK, gin.H{"mode": investigation.DefaultMode()})
		return
	}
	mode := h.inv.ReadModeFromDB(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

// Investigate triggers a (re-)investigation for an alert and returns the result.
//
//	POST /api/v1/alerts/:id/investigate
func (h *InvestigationHandler) Investigate(c *gin.Context) {
	if h.inv == nil || !h.inv.IsConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "AI investigation is not configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY.",
		})
		return
	}

	alertID := c.Param("id")
	ctx := c.Request.Context()

	result, err := h.inv.InvestigateAlert(ctx, alertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "調査の実行に失敗しました: " + err.Error(),
		})
		return
	}
	if result == nil {
		c.JSON(http.StatusOK, investigationResponse{
			AlertID:   alertID,
			Available: false,
			Summary:   "Investigation skipped (no API key configured).",
		})
		return
	}

	c.JSON(http.StatusOK, investigationResponse{
		AlertID:        result.AlertID,
		Summary:        result.Summary,
		Model:          result.Model,
		Mode:           result.Mode,
		InvestigatedAt: result.InvestigatedAt,
		Available:      true,
	})
}
