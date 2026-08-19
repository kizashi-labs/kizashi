package handlers

import (
	"errors"
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

// serveScorecard writes a scorecard, or an error when nothing in it was
// measured.
//
// scorecard.ErrNothingAssessed means every evidence query failed. Serving that
// as a 200 would put a compliance score in front of an auditor that no data
// supports, so it is a 503 — the platform's own dependency is down, which is
// what the operator needs to be told.
func serveScorecard(c *gin.Context, framework string, sc *scorecard.Scorecard, err error) {
	switch {
	case errors.Is(err, scorecard.ErrNothingAssessed):
		slog.Error("scorecard: no control could be assessed", "framework", framework)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":     "compliance evidence is unavailable; no control could be assessed",
			"framework": framework,
			"controls":  sc.Controls,
			"assessed":  sc.AssessedControls,
			"total":     sc.TotalControls,
		})
	case err != nil:
		slog.Error("scorecard: calculation failed", "framework", framework, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate " + framework + " scorecard"})
	default:
		c.JSON(http.StatusOK, sc)
	}
}

// GetNISTCSF returns the NIST Cybersecurity Framework compliance scorecard.
// GET /api/v1/admin/scorecard/nist-csf
func (h *ScorecardHandler) GetNISTCSF(c *gin.Context) {
	sc, err := h.scorer.CalculateNISTCSF(c.Request.Context())
	serveScorecard(c, "NIST_CSF", sc, err)
}

// GetISO27001 returns the ISO 27001 compliance scorecard.
// GET /api/v1/admin/scorecard/iso27001
func (h *ScorecardHandler) GetISO27001(c *gin.Context) {
	sc, err := h.scorer.CalculateISO27001(c.Request.Context())
	serveScorecard(c, "ISO27001", sc, err)
}

// GetSummary returns a brief summary of both frameworks.
// GET /api/v1/admin/scorecard/summary
func (h *ScorecardHandler) GetSummary(c *gin.Context) {
	ctx := c.Request.Context()

	// A framework whose evidence could not be read has no score. It used to be
	// substituted with OverallScore 0, which the dashboard renders in red as a
	// failing posture — the summary's own fallback invented the worst possible
	// finding out of an outage. nil now, and the JSON says null.
	nist, nistErr := h.scorer.CalculateNISTCSF(ctx)
	if nistErr != nil {
		slog.Warn("scorecard: NIST CSF calculation failed", "error", nistErr)
	}
	iso, isoErr := h.scorer.CalculateISO27001(ctx)
	if isoErr != nil {
		slog.Warn("scorecard: ISO 27001 calculation failed", "error", isoErr)
	}

	// scoreOrNil reports the framework's score only when something was measured.
	scoreOrNil := func(sc *scorecard.Scorecard, err error) *float64 {
		if err != nil || sc == nil || sc.AssessedControls == 0 {
			return nil
		}
		v := sc.OverallScore
		return &v
	}

	// Collect top gaps (worst controls from both frameworks)
	type gap struct {
		Framework string  `json:"framework"`
		ControlID string  `json:"control_id"`
		Name      string  `json:"name"`
		Score     float64 `json:"score"`
		Status    string  `json:"status"`
	}

	// A gap is a control that was assessed and fell short. An unassessed control
	// scores 0, so including it would put it at the head of a list titled "top
	// gaps" — presenting a query failure as the customer's single worst control.
	var topGaps []gap
	collect := func(framework string, sc *scorecard.Scorecard) {
		if sc == nil {
			return
		}
		for _, ctrl := range sc.Controls {
			if ctrl.Status == scorecard.StatusCompliant || ctrl.Status == scorecard.StatusNotAssessed {
				continue
			}
			topGaps = append(topGaps, gap{
				Framework: framework,
				ControlID: ctrl.ID,
				Name:      ctrl.Name,
				Score:     ctrl.Score,
				Status:    ctrl.Status,
			})
		}
	}
	collect("NIST_CSF", nist)
	collect("ISO27001", iso)

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

	coverage := func(sc *scorecard.Scorecard) gin.H {
		if sc == nil {
			return gin.H{"assessed": 0, "total": 0}
		}
		return gin.H{"assessed": sc.AssessedControls, "total": sc.TotalControls}
	}
	categories := func(sc *scorecard.Scorecard) map[string]float64 {
		if sc == nil {
			return map[string]float64{}
		}
		return sc.CategoryScores
	}

	c.JSON(http.StatusOK, gin.H{
		"nist_score":           scoreOrNil(nist, nistErr),
		"iso_score":            scoreOrNil(iso, isoErr),
		"nist_coverage":        coverage(nist),
		"iso_coverage":         coverage(iso),
		"top_gaps":             topGaps,
		"generated_at":         time.Now().UTC(),
		"nist_category_scores": categories(nist),
		"iso_category_scores":  categories(iso),
	})
}
