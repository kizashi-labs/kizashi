package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detection"
)

// CurateHandler exposes staged-curate control for SigmaHQ-synced rules (roadmap
// P1): inspect how many synced rules are field-supported/enabled/pending, advance
// a bounded curate round, and quarantine noisy rules — the API form of what was
// the curate-analyze CLI + manual SQL.
type CurateHandler struct {
	svc *detection.CurateService
}

// NewCurateHandler builds a CurateHandler. pub may be nil (no live reload signal).
func NewCurateHandler(pool *pgxpool.Pool, pub detection.CuratePublisher) *CurateHandler {
	return &CurateHandler{svc: detection.NewCurateService(pool, pub)}
}

// GetStatus handles GET /api/v1/admin/detection/curate/status — per-category
// counts of synced rules (total/supported/enabled/deferred/pending/quarantined).
func (h *CurateHandler) GetStatus(c *gin.Context) {
	status, err := h.svc.Status(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute curate status"})
		return
	}
	c.JSON(http.StatusOK, status)
}

// RunRound handles POST /api/v1/admin/detection/curate/run — enable one bounded,
// field-supported batch. Body: {"categories": ["registry_set", ...], "cap": 25}.
// categories omitted/empty = all; cap omitted/<=0 = no cap (enable every supported
// rule, used sparingly).
func (h *CurateHandler) RunRound(c *gin.Context) {
	var req struct {
		Categories []string `json:"categories"`
		Cap        int      `json:"cap"`
	}
	// Body is optional; a bare POST runs an uncapped, all-category round.
	_ = c.ShouldBindJSON(&req)

	res, err := h.svc.RunRound(c.Request.Context(), req.Categories, req.Cap)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to run curate round"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Quarantine handles POST /api/v1/admin/detection/curate/quarantine — manually
// disable noisy synced rules. Body: {"rule_ids": ["..."], "reason": "..."}.
func (h *CurateHandler) Quarantine(c *gin.Context) {
	var req struct {
		RuleIDs []string `json:"rule_ids"`
		Reason  string   `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_ids is required"})
		return
	}
	if req.Reason == "" {
		req.Reason = "manually quarantined"
	}
	n, err := h.svc.Quarantine(c.Request.Context(), req.RuleIDs, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to quarantine rules"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"quarantined": n})
}
