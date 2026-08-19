package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/compliance"
)

// ComplianceCheckerHandler exposes real-time endpoint compliance check endpoints.
type ComplianceCheckerHandler struct {
	checker *compliance.Checker
}

// NewComplianceCheckerHandler creates a new ComplianceCheckerHandler.
func NewComplianceCheckerHandler(pool *pgxpool.Pool) *ComplianceCheckerHandler {
	return &ComplianceCheckerHandler{
		checker: compliance.NewChecker(pool),
	}
}

// GetFleetCompliance handles GET /api/v1/admin/compliance/fleet
func (h *ComplianceCheckerHandler) GetFleetCompliance(c *gin.Context) {
	fleet, err := h.checker.GetFleetCompliance(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch fleet compliance"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"agents": fleet,
		"count":  len(fleet),
	})
}

// GetAgentCompliance handles GET /api/v1/admin/compliance/agent/:id
func (h *ComplianceCheckerHandler) GetAgentCompliance(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	result, err := h.checker.AssessAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assess agent compliance"})
		return
	}
	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetComplianceStats handles GET /api/v1/admin/compliance/stats
func (h *ComplianceCheckerHandler) GetComplianceStats(c *gin.Context) {
	stats, err := h.checker.GetComplianceStats(c.Request.Context())
	if err != nil {
		slog.Error("compliance: 準拠状況の集計を読めませんでした", "error", err)
		ReadFailure(c, err, stats)
		return
	}
	c.JSON(http.StatusOK, stats)
}
