package handlers

// ProcessBlockHandler provides CRUD endpoints for process execution blocking rules.
// Rules are stored in the process_block_rules table and fetched by agents on their
// polling cycle. The agent uses them to alert on or kill matching processes.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// ProcessBlockHandler handles process block rule API requests.
type ProcessBlockHandler struct {
	store *store.ProcessBlockRuleStore
}

// NewProcessBlockHandler creates a new ProcessBlockHandler.
func NewProcessBlockHandler(s *store.ProcessBlockRuleStore) *ProcessBlockHandler {
	return &ProcessBlockHandler{store: s}
}

// validProcessBlockRuleTypes mirrors the CHECK constraints in the process_block_rules table.
var validProcessBlockRuleTypes = map[string]struct{}{
	"allow": {},
	"deny":  {},
}

var validProcessBlockScopes = map[string]struct{}{
	"all":   {},
	"group": {},
	"agent": {},
}

var validProcessBlockActions = map[string]struct{}{
	"alert":           {},
	"block":           {},
	"alert_and_block": {},
}

var validProcessBlockSeverities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// processBlockRuleRequest is the shared request body for Create and Update.
type processBlockRuleRequest struct {
	Name        string  `json:"name" binding:"required"`
	ProcessName string  `json:"process_name"`
	RuleType    string  `json:"rule_type"`
	Scope       string  `json:"scope"`
	ScopeID     *string `json:"scope_id,omitempty"`
	Action      string  `json:"action"`
	Enabled     bool    `json:"enabled"`
	Severity    string  `json:"severity"`
}

func validateProcessBlockRequest(req *processBlockRuleRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name は必須です"
	}
	if strings.TrimSpace(req.ProcessName) == "" {
		return "process_name は必須です"
	}
	if req.RuleType == "" {
		req.RuleType = "deny"
	}
	if _, ok := validProcessBlockRuleTypes[req.RuleType]; !ok {
		return "rule_type は allow/deny のいずれかを指定してください"
	}
	if req.Scope == "" {
		req.Scope = "all"
	}
	if _, ok := validProcessBlockScopes[req.Scope]; !ok {
		return "scope は all/group/agent のいずれかを指定してください"
	}
	if req.Scope != "all" && (req.ScopeID == nil || strings.TrimSpace(*req.ScopeID) == "") {
		return "scope が all 以外の場合、scope_id は必須です"
	}
	if req.Action == "" {
		req.Action = "alert"
	}
	if _, ok := validProcessBlockActions[req.Action]; !ok {
		return "action は alert/block/alert_and_block のいずれかを指定してください"
	}
	if req.Severity == "" {
		req.Severity = "high"
	}
	if _, ok := validProcessBlockSeverities[req.Severity]; !ok {
		return "severity は low/medium/high/critical のいずれかを指定してください"
	}
	return ""
}

// List returns process block rules with optional filtering and pagination.
// GET /api/v1/process-rules
func (h *ProcessBlockHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page > 1 && offset == 0 {
		offset = (page - 1) * limit
	}

	var enabledPtr *bool
	if raw := c.Query("enabled"); raw != "" {
		b := raw == "true" || raw == "1"
		enabledPtr = &b
	}

	f := store.ProcessBlockRuleFilter{
		RuleType: c.Query("rule_type"),
		Scope:    c.Query("scope"),
		Enabled:  enabledPtr,
		Limit:    limit,
		Offset:   offset,
	}

	rules, total, err := h.store.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":     rules,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Create inserts a new process block rule (admin only).
// POST /api/v1/process-rules
func (h *ProcessBlockHandler) Create(c *gin.Context) {
	var req processBlockRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateProcessBlockRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.CreateProcessBlockRuleInput{
		Name:        req.Name,
		ProcessName: req.ProcessName,
		RuleType:    req.RuleType,
		Scope:       req.Scope,
		ScopeID:     req.ScopeID,
		Action:      req.Action,
		Enabled:     req.Enabled,
		Severity:    req.Severity,
	}

	rule, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update replaces an existing process block rule (admin only).
// PUT /api/v1/process-rules/:id
func (h *ProcessBlockHandler) Update(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "プロセスブロックルールが見つかりません"})
		return
	}

	// Pre-populate request with existing values so partial payloads work.
	req := processBlockRuleRequest{
		Name:        existing.Name,
		ProcessName: existing.ProcessName,
		RuleType:    existing.RuleType,
		Scope:       existing.Scope,
		ScopeID:     existing.ScopeID,
		Action:      existing.Action,
		Enabled:     existing.Enabled,
		Severity:    existing.Severity,
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateProcessBlockRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.UpdateProcessBlockRuleInput{
		Name:        req.Name,
		ProcessName: req.ProcessName,
		RuleType:    req.RuleType,
		Scope:       req.Scope,
		ScopeID:     req.ScopeID,
		Action:      req.Action,
		Enabled:     req.Enabled,
		Severity:    req.Severity,
	}

	rule, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes a process block rule by ID (admin only).
// DELETE /api/v1/process-rules/:id
func (h *ProcessBlockHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "プロセスブロックルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルールの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プロセスブロックルールを削除しました"})
}

// Toggle flips the enabled state of a process block rule (admin only).
// PATCH /api/v1/process-rules/:id/toggle
func (h *ProcessBlockHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "プロセスブロックルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// ListForAgent returns enabled rules applicable to a specific agent.
// GET /api/v1/process-rules/agent/:agent_id
// This endpoint is used by agents to fetch their applicable rules on a polling cycle.
func (h *ProcessBlockHandler) ListForAgent(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id は必須です"})
		return
	}

	rules, err := h.store.ListForAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェント向けルールの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}
