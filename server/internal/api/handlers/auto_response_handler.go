package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// AutoResponseHandler handles auto response rule endpoints.
type AutoResponseHandler struct {
	store *store.AutoResponseStore
}

// NewAutoResponseHandler creates a new AutoResponseHandler.
func NewAutoResponseHandler(s *store.AutoResponseStore) *AutoResponseHandler {
	return &AutoResponseHandler{store: s}
}

// List returns all auto response rules.
func (h *AutoResponseHandler) List(c *gin.Context) {
	rules, err := h.store.ListRules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// Create inserts a new auto response rule.
func (h *AutoResponseHandler) Create(c *gin.Context) {
	var in store.CreateAutoResponseRuleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule, err := h.store.CreateRule(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Get returns a single auto response rule by ID.
func (h *AutoResponseHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.GetRule(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Update modifies an existing auto response rule.
func (h *AutoResponseHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var in store.UpdateAutoResponseRuleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule, err := h.store.UpdateRule(c.Request.Context(), id, in)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "auto response rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes an auto response rule by ID.
func (h *AutoResponseHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteRule(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// Toggle flips the enabled state of an auto response rule.
func (h *AutoResponseHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.ToggleRule(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// ListExecutions returns the executions for a given auto response rule.
func (h *AutoResponseHandler) ListExecutions(c *gin.Context) {
	id := c.Param("id")
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}
	execs, err := h.store.ListExecutionsByRule(c.Request.Context(), id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"executions": execs})
}
