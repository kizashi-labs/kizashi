package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// policyCommander dispatches apply_policy commands to agents.
type policyCommander interface {
	EnqueueApplyPolicy(agentID string, payload store.ApplyPolicyPayload) error
}

// AgentPolicyHandler provides agent policy management endpoints.
type AgentPolicyHandler struct {
	store      *store.AgentPolicyStore
	agentStore *store.AgentStore
	commander  policyCommander
}

// NewAgentPolicyHandler creates a new AgentPolicyHandler.
func NewAgentPolicyHandler(s *store.AgentPolicyStore) *AgentPolicyHandler {
	return &AgentPolicyHandler{store: s}
}

// NewAgentPolicyHandlerWithCommander creates a new AgentPolicyHandler with gRPC dispatch support.
func NewAgentPolicyHandlerWithCommander(s *store.AgentPolicyStore, as *store.AgentStore, cmd policyCommander) *AgentPolicyHandler {
	return &AgentPolicyHandler{store: s, agentStore: as, commander: cmd}
}

// validLogLevels is the set of acceptable log level values.
var validLogLevels = map[string]struct{}{
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

// policyRequest is the shared request body for Create and Update.
type policyRequest struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	TenantID            string   `json:"tenant_id"`
	ScanIntervalMin     int      `json:"scan_interval_min"`
	FullScanHour        int      `json:"full_scan_hour"`
	MonitoredExtensions []string `json:"monitored_extensions"`
	ExcludedPaths       []string `json:"excluded_paths"`
	CPULimitPct         int      `json:"cpu_limit_pct"`
	MemLimitMB          int      `json:"mem_limit_mb"`
	MonitorNetwork      bool     `json:"monitor_network"`
	MonitorDNS          bool     `json:"monitor_dns"`
	LogLevel            string   `json:"log_level"`
}

// validatePolicy checks the policy fields and returns the first error message,
// or an empty string if everything is valid.
func validatePolicy(req *policyRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name は必須です"
	}
	if req.ScanIntervalMin < 5 || req.ScanIntervalMin > 1440 {
		return "scan_interval_min は 5〜1440 の範囲で指定してください"
	}
	if req.FullScanHour < 0 || req.FullScanHour > 23 {
		return "full_scan_hour は 0〜23 の範囲で指定してください"
	}
	if req.CPULimitPct < 5 || req.CPULimitPct > 80 {
		return "cpu_limit_pct は 5〜80 の範囲で指定してください"
	}
	if req.MemLimitMB < 64 {
		return "mem_limit_mb は 64 以上を指定してください"
	}
	if _, ok := validLogLevels[req.LogLevel]; !ok {
		return "log_level は debug/info/warn/error のいずれかを指定してください"
	}
	return ""
}

// applyDefaults fills in zero values with sensible defaults.
func applyDefaults(req *policyRequest) {
	if req.ScanIntervalMin == 0 {
		req.ScanIntervalMin = 60
	}
	if req.CPULimitPct == 0 {
		req.CPULimitPct = 20
	}
	if req.MemLimitMB == 0 {
		req.MemLimitMB = 256
	}
	if req.LogLevel == "" {
		req.LogLevel = "info"
	}
	if req.MonitoredExtensions == nil {
		req.MonitoredExtensions = []string{".exe", ".dll", ".sh", ".ps1", ".py"}
	}
	if req.ExcludedPaths == nil {
		req.ExcludedPaths = []string{}
	}
}

// List returns all agent policies.
// GET /api/v1/agent-policies
func (h *AgentPolicyHandler) List(c *gin.Context) {
	policies, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシー一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": policies, "total": len(policies)})
}

// Get returns a single agent policy by ID.
// GET /api/v1/agent-policies/:id
func (h *AgentPolicyHandler) Get(c *gin.Context) {
	id := c.Param("id")
	policy, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// Create creates a new agent policy (admin only).
// POST /api/v1/agent-policies
func (h *AgentPolicyHandler) Create(c *gin.Context) {
	var req policyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	applyDefaults(&req)

	if msg := validatePolicy(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.CreatePolicyInput{
		Name:                req.Name,
		Description:         req.Description,
		TenantID:            req.TenantID,
		ScanIntervalMin:     req.ScanIntervalMin,
		FullScanHour:        req.FullScanHour,
		MonitoredExtensions: req.MonitoredExtensions,
		ExcludedPaths:       req.ExcludedPaths,
		CPULimitPct:         req.CPULimitPct,
		MemLimitMB:          req.MemLimitMB,
		MonitorNetwork:      req.MonitorNetwork,
		MonitorDNS:          req.MonitorDNS,
		LogLevel:            req.LogLevel,
	}

	policy, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, policy)
}

// Update updates an existing agent policy (admin only).
// PUT /api/v1/agent-policies/:id
func (h *AgentPolicyHandler) Update(c *gin.Context) {
	id := c.Param("id")

	// まず既存のポリシーを取得してフォームの初期値とする
	existing, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}

	// 既存値でリクエストを初期化してから上書き
	req := policyRequest{
		Name:                existing.Name,
		Description:         existing.Description,
		TenantID:            existing.TenantID,
		ScanIntervalMin:     existing.ScanIntervalMin,
		FullScanHour:        existing.FullScanHour,
		MonitoredExtensions: existing.MonitoredExtensions,
		ExcludedPaths:       existing.ExcludedPaths,
		CPULimitPct:         existing.CPULimitPct,
		MemLimitMB:          existing.MemLimitMB,
		MonitorNetwork:      existing.MonitorNetwork,
		MonitorDNS:          existing.MonitorDNS,
		LogLevel:            existing.LogLevel,
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if msg := validatePolicy(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.UpdatePolicyInput{
		Name:                req.Name,
		Description:         req.Description,
		ScanIntervalMin:     req.ScanIntervalMin,
		FullScanHour:        req.FullScanHour,
		MonitoredExtensions: req.MonitoredExtensions,
		ExcludedPaths:       req.ExcludedPaths,
		CPULimitPct:         req.CPULimitPct,
		MemLimitMB:          req.MemLimitMB,
		MonitorNetwork:      req.MonitorNetwork,
		MonitorDNS:          req.MonitorDNS,
		LogLevel:            req.LogLevel,
	}

	policy, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// Delete removes an agent policy by ID (admin only).
// DELETE /api/v1/agent-policies/:id
func (h *AgentPolicyHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		// デフォルトポリシー削除試行
		if strings.Contains(err.Error(), "デフォルトポリシー") {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを削除しました"})
}

// Assign assigns a policy to an agent group.
// PUT /api/v1/groups/:id/policy
func (h *AgentPolicyHandler) Assign(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		PolicyID string `json:"policy_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy_id は必須です"})
		return
	}

	// policy_id が実在するか確認し、後で配布用に取得する
	policy, err := h.store.Get(c.Request.Context(), req.PolicyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "指定されたポリシーが見つかりません"})
		return
	}

	if err := h.store.AssignToGroup(c.Request.Context(), groupID, req.PolicyID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "グループが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの割り当てに失敗しました"})
		return
	}

	// Push the policy to all agents in the group via gRPC (best-effort).
	if h.commander != nil && h.agentStore != nil {
		agents, _, err := h.agentStore.ListAgents(c.Request.Context(), store.AgentFilter{
			GroupID: groupID,
			Limit:   10000,
		})
		if err != nil {
			slog.Warn("apply_policy: グループのエージェント一覧取得に失敗しました", "group", groupID, "error", err)
		} else {
			payload := store.ApplyPolicyPayload{
				PolicyID:        policy.ID,
				ScanIntervalMin: policy.ScanIntervalMin,
				CPULimitPct:     policy.CPULimitPct,
				EnabledModules:  buildEnabledModules(policy),
			}
			for _, agent := range agents {
				if err := h.commander.EnqueueApplyPolicy(agent.ID, payload); err != nil {
					slog.Warn("apply_policy: エージェントへのコマンド送信に失敗しました",
						"agent", agent.ID, "error", err)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを割り当てました"})
}

// buildEnabledModules derives the list of enabled module names from a policy.
func buildEnabledModules(p *store.AgentPolicy) []string {
	var modules []string
	if p.MonitorNetwork {
		modules = append(modules, "network")
	}
	if p.MonitorDNS {
		modules = append(modules, "dns")
	}
	return modules
}
