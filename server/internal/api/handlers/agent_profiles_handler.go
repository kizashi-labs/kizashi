package handlers

import (
	"log/slog"
	"net/http"

	"github.com/edr-platform/server/internal/agentconfig"
	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
)

// AgentProfilesHandler provides endpoints for managing agent configuration profiles.
type AgentProfilesHandler struct {
	store    *agentconfig.Store
	natsConn *nats.Conn
}

// NewAgentProfilesHandler creates a new AgentProfilesHandler.
func NewAgentProfilesHandler(store *agentconfig.Store, natsConn *nats.Conn) *AgentProfilesHandler {
	return &AgentProfilesHandler{store: store, natsConn: natsConn}
}

// ListProfiles returns all agent configuration profiles.
// GET /api/v1/admin/agent-profiles
func (h *AgentProfilesHandler) ListProfiles(c *gin.Context) {
	profiles, err := h.store.ListProfiles(c.Request.Context())
	if err != nil {
		slog.Error("agent_profiles: failed to list", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list profiles"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"profiles": profiles, "total": len(profiles)})
}

// CreateProfile creates a new agent configuration profile.
// POST /api/v1/admin/agent-profiles
func (h *AgentProfilesHandler) CreateProfile(c *gin.Context) {
	var profile agentconfig.Profile
	if err := c.ShouldBindJSON(&profile); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created, err := h.store.CreateProfile(c.Request.Context(), &profile)
	if err != nil {
		slog.Error("agent_profiles: failed to create", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create profile"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// GetProfile returns a single agent configuration profile.
// GET /api/v1/admin/agent-profiles/:id
func (h *AgentProfilesHandler) GetProfile(c *gin.Context) {
	id := c.Param("id")
	profile, err := h.store.GetProfile(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

// UpdateProfile updates an existing agent configuration profile.
// PUT /api/v1/admin/agent-profiles/:id
func (h *AgentProfilesHandler) UpdateProfile(c *gin.Context) {
	id := c.Param("id")
	var updates agentconfig.Profile
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.store.UpdateProfile(c.Request.Context(), id, &updates)
	if err != nil {
		slog.Error("agent_profiles: failed to update", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// DeleteProfile deletes an agent configuration profile.
// DELETE /api/v1/admin/agent-profiles/:id
func (h *AgentProfilesHandler) DeleteProfile(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteProfile(c.Request.Context(), id); err != nil {
		slog.Error("agent_profiles: failed to delete", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete profile"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// PushProfile pushes a configuration profile to a specific agent.
// POST /api/v1/admin/agent-profiles/:id/push
// Body: {"agent_id": "..."}
func (h *AgentProfilesHandler) PushProfile(c *gin.Context) {
	profileID := c.Param("id")
	var req struct {
		AgentID string `json:"agent_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.PushToAgent(c.Request.Context(), req.AgentID, profileID, h.natsConn); err != nil {
		slog.Error("agent_profiles: failed to push config", "profile_id", profileID, "agent_id", req.AgentID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"pushed":     true,
		"agent_id":   req.AgentID,
		"profile_id": profileID,
	})
}

// PushProfileAll pushes a configuration profile to all agents matching the profile's OS type.
// POST /api/v1/admin/agent-profiles/:id/push-all
func (h *AgentProfilesHandler) PushProfileAll(c *gin.Context) {
	profileID := c.Param("id")

	profile, err := h.store.GetProfile(c.Request.Context(), profileID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	agentIDs, err := h.store.ListAgentsByOSType(c.Request.Context(), profile.OSType)
	if err != nil {
		slog.Error("agent_profiles: failed to list agents", "os_type", profile.OSType, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list agents"})
		return
	}

	pushed := 0
	failed := 0
	for _, agentID := range agentIDs {
		if err := h.store.PushToAgent(c.Request.Context(), agentID, profileID, h.natsConn); err != nil {
			slog.Warn("agent_profiles: push failed", "agent_id", agentID, "error", err)
			failed++
		} else {
			pushed++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"profile_id": profileID,
		"os_type":    profile.OSType,
		"pushed":     pushed,
		"failed":     failed,
		"total":      len(agentIDs),
	})
}
