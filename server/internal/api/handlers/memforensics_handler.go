package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/memforensics"
)

// MemForensicsHandler exposes memory forensics analysis endpoints.
type MemForensicsHandler struct {
	analyzer *memforensics.Analyzer
}

// NewMemForensicsHandler creates a new MemForensicsHandler.
func NewMemForensicsHandler(pool *pgxpool.Pool) *MemForensicsHandler {
	return &MemForensicsHandler{
		analyzer: memforensics.NewAnalyzer(pool),
	}
}

// GetArtifacts handles GET /api/v1/admin/memory/artifacts
// Query params: hours (default 24), agent_id (optional)
func (h *MemForensicsHandler) GetArtifacts(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 {
		hours = 24
	}
	agentID := c.Query("agent_id")

	artifacts, err := h.analyzer.GetArtifacts(c.Request.Context(), agentID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch memory artifacts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"artifacts": artifacts,
		"count":     len(artifacts),
	})
}

// DetectInjection handles GET /api/v1/admin/memory/injection
// Query params: hours (default 24)
func (h *MemForensicsHandler) DetectInjection(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 {
		hours = 24
	}

	artifacts, err := h.analyzer.DetectInjection(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "injection detection failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"artifacts": artifacts,
		"count":     len(artifacts),
	})
}

// GetStats handles GET /api/v1/admin/memory/stats
func (h *MemForensicsHandler) GetStats(c *gin.Context) {
	stats := h.analyzer.GetStats(c.Request.Context())
	c.JSON(http.StatusOK, stats)
}
