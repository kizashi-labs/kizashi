package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/compliance"
)

// ComplianceEvalHandler exposes auto-evaluation endpoints for the compliance engine.
type ComplianceEvalHandler struct {
	evaluator *compliance.Evaluator
}

// NewComplianceEvalHandler creates a new ComplianceEvalHandler.
func NewComplianceEvalHandler(pool *pgxpool.Pool) *ComplianceEvalHandler {
	return &ComplianceEvalHandler{
		evaluator: compliance.NewEvaluator(pool),
	}
}

// parseFramework extracts and validates the ?framework= query parameter.
// Defaults to CIS if not provided.
func parseFramework(c *gin.Context) compliance.Framework {
	fw := c.Query("framework")
	switch compliance.Framework(fw) {
	case compliance.FrameworkCIS, compliance.FrameworkNIST, compliance.FrameworkSOC2:
		return compliance.Framework(fw)
	default:
		return compliance.FrameworkCIS
	}
}

// GetAgentReport handles GET /api/v1/compliance/agents/:id
// Returns the latest stored compliance report for an agent.
// Query param: ?framework=cis|nist|soc2 (default: cis)
func (h *ComplianceEvalHandler) GetAgentReport(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	fw := parseFramework(c)
	report, err := h.evaluator.GetLatestReport(c.Request.Context(), agentID, fw)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":  "no compliance report found for agent",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, report)
}

// EvaluateAgent handles POST /api/v1/compliance/agents/:id/evaluate
// Triggers a live compliance evaluation for the specified agent.
// Query param: ?framework=cis|nist|soc2 (default: cis)
func (h *ComplianceEvalHandler) EvaluateAgent(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	fw := parseFramework(c)
	report, err := h.evaluator.EvaluateAgent(c.Request.Context(), agentID, fw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "evaluation failed",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, report)
}

// GetOrgSummary handles GET /api/v1/compliance/summary
// Returns the org-wide average compliance score per framework.
func (h *ComplianceEvalHandler) GetOrgSummary(c *gin.Context) {
	summaries, err := h.evaluator.GetOrgSummary(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "failed to retrieve compliance summary",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"summaries": summaries,
		"count":     len(summaries),
	})
}
