package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/scorecard"
	"github.com/gin-gonic/gin"
)

// ScorecardHandler provides compliance scorecard endpoints.
type ScorecardHandler struct {
	scorer *scorecard.Scorer
}

// NewScorecardHandler creates a new ScorecardHandler.
func NewScorecardHandler(scorer *scorecard.Scorer) *ScorecardHandler {
	return &ScorecardHandler{scorer: scorer}
}

// GetNISTCSF returns the NIST Cybersecurity Framework compliance scorecard.
// GET /api/v1/admin/scorecard/nist-csf
func (h *ScorecardHandler) GetNISTCSF(c *gin.Context) {
	sc, err := h.scorer.CalculateNISTCSF(c.Request.Context())
	if err != nil {
		slog.Error("scorecard: NIST CSF calculation failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate NIST CSF scorecard"})
		return
	}
	c.JSON(http.StatusOK, sc)
}

// GetISO27001 returns the ISO 27001 compliance scorecard.
// GET /api/v1/admin/scorecard/iso27001
func (h *ScorecardHandler) GetISO27001(c *gin.Context) {
	sc, err := h.scorer.CalculateISO27001(c.Request.Context())
	if err != nil {
		slog.Error("scorecard: ISO 27001 calculation failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate ISO 27001 scorecard"})
		return
	}
	c.JSON(http.StatusOK, sc)
}

// GetSummary returns a brief summary of both frameworks.
// GET /api/v1/admin/scorecard/summary
func (h *ScorecardHandler) GetSummary(c *gin.Context) {
	ctx := c.Request.Context()

	nist, err := h.scorer.CalculateNISTCSF(ctx)
	if err != nil {
		slog.Warn("scorecard: NIST CSF calculation failed", "error", err)
		nist = &scorecard.Scorecard{Framework: "NIST_CSF", OverallScore: 0}
	}

	iso, err := h.scorer.CalculateISO27001(ctx)
	if err != nil {
		slog.Warn("scorecard: ISO 27001 calculation failed", "error", err)
		iso = &scorecard.Scorecard{Framework: "ISO27001", OverallScore: 0}
	}

	// Collect top gaps (worst controls from both frameworks)
	type gap struct {
		Framework string  `json:"framework"`
		ControlID string  `json:"control_id"`
		Name      string  `json:"name"`
		Score     float64 `json:"score"`
		Status    string  `json:"status"`
	}

	var topGaps []gap
	for _, ctrl := range nist.Controls {
		if ctrl.Status != "compliant" {
			topGaps = append(topGaps, gap{
				Framework: "NIST_CSF",
				ControlID: ctrl.ID,
				Name:      ctrl.Name,
				Score:     ctrl.Score,
				Status:    ctrl.Status,
			})
		}
	}
	for _, ctrl := range iso.Controls {
		if ctrl.Status != "compliant" {
			topGaps = append(topGaps, gap{
				Framework: "ISO27001",
				ControlID: ctrl.ID,
				Name:      ctrl.Name,
				Score:     ctrl.Score,
				Status:    ctrl.Status,
			})
		}
	}

	// Sort by score ascending (worst first) and take top 5
	for i := 0; i < len(topGaps)-1; i++ {
		for j := i + 1; j < len(topGaps); j++ {
			if topGaps[j].Score < topGaps[i].Score {
				topGaps[i], topGaps[j] = topGaps[j], topGaps[i]
			}
		}
	}
	if len(topGaps) > 5 {
		topGaps = topGaps[:5]
	}
	if topGaps == nil {
		topGaps = []gap{}
	}

	c.JSON(http.StatusOK, gin.H{
		"nist_score":           nist.OverallScore,
		"iso_score":            iso.OverallScore,
		"top_gaps":             topGaps,
		"generated_at":         time.Now().UTC(),
		"nist_category_scores": nist.CategoryScores,
		"iso_category_scores":  iso.CategoryScores,
	})
}
