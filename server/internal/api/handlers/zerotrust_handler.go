package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/zerotrust"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ZeroTrustEngineHandler wraps the in-memory Zero Trust engine for API access.
// It is distinct from ZeroTrustHandler (zero_trust_handler.go) which operates
// against the database-backed policy table.
type ZeroTrustEngineHandler struct {
	engine *zerotrust.Engine
}

func NewZeroTrustEngineHandler(engine *zerotrust.Engine) *ZeroTrustEngineHandler {
	return &ZeroTrustEngineHandler{engine: engine}
}

// GetPolicies returns all Zero Trust policies
// GET /api/v1/admin/zero-trust/engine/policies
func (h *ZeroTrustEngineHandler) GetPolicies(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"policies": h.engine.GetPolicies()})
}

// CreatePolicy creates a new policy
// POST /api/v1/admin/zero-trust/engine/policies
func (h *ZeroTrustEngineHandler) CreatePolicy(c *gin.Context) {
	var policy zerotrust.ZeroTrustPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	h.engine.UpdatePolicy(policy)
	c.JSON(http.StatusCreated, policy)
}

// UpdatePolicy updates an existing policy
// PUT /api/v1/admin/zero-trust/engine/policies/:id
func (h *ZeroTrustEngineHandler) UpdatePolicy(c *gin.Context) {
	var policy zerotrust.ZeroTrustPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy.ID = c.Param("id")
	h.engine.UpdatePolicy(policy)
	c.JSON(http.StatusOK, policy)
}

// DeletePolicy deletes a policy by ID
// DELETE /api/v1/admin/zero-trust/engine/policies/:id
func (h *ZeroTrustEngineHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	if !h.engine.DeletePolicy(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを削除しました"})
}

// GetPostures returns all device postures
// GET /api/v1/admin/zero-trust/engine/postures
func (h *ZeroTrustEngineHandler) GetPostures(c *gin.Context) {
	postures := h.engine.GetAllPostures()
	c.JSON(http.StatusOK, gin.H{"postures": postures, "count": len(postures)})
}

// EvaluateDevice evaluates a specific device's trust score
// POST /api/v1/admin/zero-trust/engine/evaluate/:agent_id
func (h *ZeroTrustEngineHandler) EvaluateDevice(c *gin.Context) {
	agentID := c.Param("agent_id")
	posture, err := h.engine.EvaluateDevice(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, posture)
}

// CheckAccess checks if a device can access a resource
// GET /api/v1/admin/zero-trust/engine/check
func (h *ZeroTrustEngineHandler) CheckAccess(c *gin.Context) {
	agentID := c.Query("agent_id")
	resource := c.Query("resource")
	if agentID == "" || resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idとresourceが必要です"})
		return
	}
	decision := h.engine.CheckAccess(agentID, resource)
	c.JSON(http.StatusOK, decision)
}
