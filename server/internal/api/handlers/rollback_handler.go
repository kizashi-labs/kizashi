package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/rollback"
)

// rollbackPlanner is the slice of RollbackService the handler needs (so the concrete
// service satisfies it and tests can fake it).
type rollbackPlanner interface {
	Plan(ctx context.Context, incidentID string) (rollback.RollbackPlan, error)
	MarkReverted(ctx context.Context, incidentID string, paths []string) (int, error)
}

// RollbackHandler exposes incident-level rollback (SentinelOne Storyline–equivalent):
// preview the inverse operations that undo an incident's file changes, and execute
// them (Ph3 of docs/design/ロールバック(Storyline相当)設計.md). Rollback is destructive,
// so Preview and Execute are separate — no auto-apply.
type RollbackHandler struct {
	svc rollbackPlanner
	cmd rollback.Commander
}

// NewRollbackHandler builds a handler over a pool (for the journal) and a commander
// (to dispatch restore/delete to agents).
func NewRollbackHandler(pool *pgxpool.Pool, cmd rollback.Commander) *RollbackHandler {
	return &RollbackHandler{svc: rollback.NewRollbackService(pool), cmd: cmd}
}

// Preview handles GET /api/v1/admin/incidents/:id/rollback/preview — the inverse
// operations that would restore the pre-incident state, for analyst review before
// executing. needs_manual counts paths whose pre-image backup is missing.
func (h *RollbackHandler) Preview(c *gin.Context) {
	incidentID := c.Param("id")
	plan, err := h.svc.Plan(c.Request.Context(), incidentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build rollback plan"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"incident_id":  incidentID,
		"ops":          plan.Ops,
		"needs_manual": plan.NeedsManualCount(),
	})
}

// Execute handles POST /api/v1/admin/incidents/:id/rollback — dispatch the plan's
// inverse operations to the target agent and mark the successfully-reverted paths.
// Body: {"agent_id": "..."}. NeedsManual ops are reported, never auto-executed.
func (h *RollbackHandler) Execute(c *gin.Context) {
	incidentID := c.Param("id")
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}
	plan, err := h.svc.Plan(c.Request.Context(), incidentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build rollback plan"})
		return
	}
	outcomes := rollback.Execute(c.Request.Context(), req.AgentID, plan, h.cmd)
	succeeded := rollback.SucceededPaths(outcomes)
	reverted, err := h.svc.MarkReverted(c.Request.Context(), incidentID, succeeded)
	if err != nil {
		// The commands were dispatched; only the journal bookkeeping failed. Report it
		// but still return the outcomes so the operator sees what was actioned.
		c.JSON(http.StatusOK, gin.H{
			"incident_id": incidentID, "agent_id": req.AgentID,
			"outcomes": outcomes, "reverted": 0,
			"warning": "operations dispatched but journal update failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"incident_id": incidentID, "agent_id": req.AgentID,
		"outcomes": outcomes, "reverted": reverted,
	})
}
