package handlers

import (
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/remediation"
	"github.com/gin-gonic/gin"
)

// RemediationHandler provides auto-remediation rule management and execution log endpoints.
type RemediationHandler struct {
	engine *remediation.Engine
}

// NewRemediationHandler creates a new RemediationHandler.
func NewRemediationHandler(engine *remediation.Engine) *RemediationHandler {
	return &RemediationHandler{engine: engine}
}

// ListRules returns all remediation rules.
// GET /api/v1/admin/remediation/rules
func (h *RemediationHandler) ListRules(c *gin.Context) {
	rules := h.engine.GetRules()

	type ruleResponse struct {
		ID              string                          `json:"id"`
		Name            string                          `json:"name"`
		Enabled         bool                            `json:"enabled"`
		Trigger         remediation.RuleTrigger         `json:"trigger"`
		Actions         []remediation.RemediationAction `json:"actions"`
		Cooldown        string                          `json:"cooldown"`
		RollbackTimeout string                          `json:"rollback_timeout,omitempty"`
		CreatedAt       time.Time                       `json:"created_at"`
	}

	out := make([]ruleResponse, 0, len(rules))
	for _, r := range rules {
		rr := ruleResponse{
			ID:        r.ID,
			Name:      r.Name,
			Enabled:   r.Enabled,
			Trigger:   r.Trigger,
			Actions:   r.Actions,
			Cooldown:  r.Cooldown.String(),
			CreatedAt: r.CreatedAt,
		}
		if r.RollbackTimeout > 0 {
			rr.RollbackTimeout = r.RollbackTimeout.String()
		}
		out = append(out, rr)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": out,
		"total": len(out),
	})
}

// createRuleRequest is the JSON body for creating a remediation rule.
type createRuleRequest struct {
	Name    string                          `json:"name"    binding:"required"`
	Enabled *bool                           `json:"enabled"`
	Trigger remediation.RuleTrigger         `json:"trigger"`
	Actions []remediation.RemediationAction `json:"actions"`
	// CooldownSeconds overrides Cooldown duration.
	CooldownSeconds int `json:"cooldown_seconds"`
	// RollbackTimeoutSeconds: if >0 and rule isolates network, schedules auto-rollback.
	RollbackTimeoutSeconds int `json:"rollback_timeout_seconds"`
}

// CreateRule creates a new remediation rule.
// POST /api/v1/admin/remediation/rules
func (h *RemediationHandler) CreateRule(c *gin.Context) {
	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	cooldown := time.Duration(req.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	rule := &remediation.RemediationRule{
		ID:              "custom-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		Name:            req.Name,
		Enabled:         enabled,
		Trigger:         req.Trigger,
		Actions:         req.Actions,
		Cooldown:        cooldown,
		RollbackTimeout: time.Duration(req.RollbackTimeoutSeconds) * time.Second,
		CreatedAt:       time.Now().UTC(),
	}

	h.engine.AddRule(rule)

	c.JSON(http.StatusCreated, gin.H{
		"id":      rule.ID,
		"name":    rule.Name,
		"message": "remediation rule created",
	})
}

// EnableRule toggles the enabled state of a remediation rule.
// PUT /api/v1/admin/remediation/rules/:id/enable
func (h *RemediationHandler) EnableRule(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, ok := h.engine.GetRuleByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	h.engine.EnableRule(id, req.Enabled)
	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"name":    rule.Name,
		"enabled": req.Enabled,
		"message": "rule updated",
	})
}

// GetLogs returns remediation execution history with pagination.
// GET /api/v1/admin/remediation/logs?limit=20&offset=0
func (h *RemediationHandler) GetLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 || limit > 200 {
		limit = 20
	}

	logs, err := h.engine.GetExecutionLogs(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch execution logs"})
		return
	}
	if logs == nil {
		logs = []remediation.ExecutionLog{}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": len(logs),
		"limit": limit,
	})
}

// testRuleRequest is the JSON body for dry-run testing.
type testRuleRequest struct {
	EventType string   `json:"event_type"`
	Severity  int      `json:"severity"`
	Tags      []string `json:"tags"`
}

// TestRule performs a dry-run against a sample event, returning which rules would fire.
// POST /api/v1/admin/remediation/test
func (h *RemediationHandler) TestRule(c *gin.Context) {
	var req testRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.EventType == "" {
		req.EventType = "alert"
	}

	matched := h.engine.DryRun(req.EventType, req.Severity, req.Tags)
	if matched == nil {
		matched = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"dry_run":       true,
		"event_type":    req.EventType,
		"severity":      req.Severity,
		"tags":          req.Tags,
		"matched_rules": matched,
		"match_count":   len(matched),
	})
}

// ─── Exclusion list ───────────────────────────────────────────────────────────

// ListExclusions returns all hostname exclusion patterns.
// GET /api/v1/admin/remediation/exclusions
func (h *RemediationHandler) ListExclusions(c *gin.Context) {
	list := h.engine.ListExclusions()
	if list == nil {
		list = []remediation.RemediationExclusion{}
	}
	c.JSON(http.StatusOK, gin.H{
		"exclusions": list,
		"total":      len(list),
	})
}

// CreateExclusion adds a hostname glob pattern to the exclusion list.
// POST /api/v1/admin/remediation/exclusions
func (h *RemediationHandler) CreateExclusion(c *gin.Context) {
	var req struct {
		HostnamePattern string `json:"hostname_pattern" binding:"required"`
		Reason          string `json:"reason"`
		CreatedBy       string `json:"created_by"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate glob pattern syntax.
	if _, err := filepath.Match(req.HostnamePattern, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid glob pattern: " + err.Error()})
		return
	}

	createdBy := req.CreatedBy
	if createdBy == "" {
		if user, ok := c.Get("username"); ok {
			if s, ok := user.(string); ok {
				createdBy = s
			}
		}
	}

	ex := remediation.RemediationExclusion{
		HostnamePattern: req.HostnamePattern,
		Reason:          req.Reason,
		CreatedBy:       createdBy,
	}
	h.engine.AddExclusion(ex)

	// Return the newly added exclusion (last match in list).
	list := h.engine.ListExclusions()
	var created remediation.RemediationExclusion
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].HostnamePattern == req.HostnamePattern {
			created = list[i]
			break
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":               created.ID,
		"hostname_pattern": created.HostnamePattern,
		"reason":           created.Reason,
		"message":          "exclusion added",
	})
}

// DeleteExclusion removes an exclusion by ID.
// DELETE /api/v1/admin/remediation/exclusions/:id
func (h *RemediationHandler) DeleteExclusion(c *gin.Context) {
	id := c.Param("id")
	if !h.engine.RemoveExclusion(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "exclusion not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "message": "exclusion removed"})
}

// ─── Pending rollbacks ────────────────────────────────────────────────────────

// ListPendingRollbacks returns executions with pending automatic rollbacks.
// GET /api/v1/admin/remediation/pending-rollbacks
func (h *RemediationHandler) ListPendingRollbacks(c *gin.Context) {
	pending := h.engine.ListPendingRollbacks()
	if pending == nil {
		pending = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{
		"pending_rollbacks": pending,
		"total":             len(pending),
	})
}

// ApproveExecution cancels a pending automatic rollback (analyst approved the isolation).
// POST /api/v1/admin/remediation/executions/:id/approve
func (h *RemediationHandler) ApproveExecution(c *gin.Context) {
	id := c.Param("id")
	if !h.engine.ApproveExecution(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no pending rollback found for this execution"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"execution_id": id,
		"message":      "rollback cancelled — execution approved by analyst",
	})
}
