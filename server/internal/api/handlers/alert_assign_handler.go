package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// AlertAssignHandler provides CRUD endpoints for alert auto-assignment rules.
type AlertAssignHandler struct {
	store *store.AlertAssignRuleStore
}

// NewAlertAssignHandler creates a new AlertAssignHandler.
func NewAlertAssignHandler(s *store.AlertAssignRuleStore) *AlertAssignHandler {
	return &AlertAssignHandler{store: s}
}

// List returns all alert assignment rules.
// GET /api/v1/alert-assign-rules
func (h *AlertAssignHandler) List(c *gin.Context) {
	rules, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list alert assign rules"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// alertAssignRequest is the shared request body for Create and Update.
type alertAssignRequest struct {
	Name       string          `json:"name"        binding:"required"`
	Priority   int             `json:"priority"`
	Conditions json.RawMessage `json:"conditions"`
	AssigneeID string          `json:"assignee_id"`
	Enabled    bool            `json:"enabled"`
}

// Create inserts a new alert assignment rule.
// POST /api/v1/alert-assign-rules
func (h *AlertAssignHandler) Create(c *gin.Context) {
	var req alertAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.AssigneeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "assignee_id is required"})
		return
	}

	rule, err := h.store.Create(c.Request.Context(), store.CreateAssignRuleInput{
		Name:       req.Name,
		Priority:   req.Priority,
		Conditions: req.Conditions,
		AssigneeID: req.AssigneeID,
		Enabled:    req.Enabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create alert assign rule"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"rule": rule})
}

// Update modifies an existing alert assignment rule.
// PUT /api/v1/alert-assign-rules/:id
func (h *AlertAssignHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req alertAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.AssigneeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "assignee_id is required"})
		return
	}

	rule, err := h.store.Update(c.Request.Context(), id, store.UpdateAssignRuleInput{
		Name:       req.Name,
		Priority:   req.Priority,
		Conditions: req.Conditions,
		AssigneeID: req.AssigneeID,
		Enabled:    req.Enabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update alert assign rule"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rule": rule})
}

// Delete removes an alert assignment rule.
// DELETE /api/v1/alert-assign-rules/:id
func (h *AlertAssignHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}
