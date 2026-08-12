package handlers

// FIMHandler provides CRUD endpoints for File Integrity Monitoring (FIM) rules.
// Rules are stored in the fim_rules table and pushed to agents on their next
// config poll cycle. The agent uses them to extend its default watched-path set.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// FIMHandler handles FIM rule API requests.
type FIMHandler struct {
	store *store.FIMRuleStore
}

// NewFIMHandler creates a new FIMHandler.
func NewFIMHandler(s *store.FIMRuleStore) *FIMHandler {
	return &FIMHandler{store: s}
}

// validFIMSeverities mirrors the CHECK constraint in the fim_rules table.
var validFIMSeverities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// fimRuleRequest is the shared request body for Create and Update.
type fimRuleRequest struct {
	Name            string   `json:"name" binding:"required"`
	Path            string   `json:"path"`
	Recursive       bool     `json:"recursive"`
	ExcludePatterns []string `json:"exclude_patterns"`
	Enabled         bool     `json:"enabled"`
	Severity        string   `json:"severity"`
}

func validateFIMRequest(req *fimRuleRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name は必須です"
	}
	if strings.TrimSpace(req.Path) == "" {
		return "path は必須です"
	}
	if req.Severity == "" {
		req.Severity = "high"
	}
	if _, ok := validFIMSeverities[req.Severity]; !ok {
		return "severity は low/medium/high/critical のいずれかを指定してください"
	}
	return ""
}

// List returns FIM rules with optional filtering and pagination.
// GET /api/v1/fim-rules
func (h *FIMHandler) List(c *gin.Context) {
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

	f := store.FIMRuleFilter{
		Enabled:  enabledPtr,
		Severity: c.Query("severity"),
		Limit:    limit,
		Offset:   offset,
	}

	rules, total, err := h.store.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FIMルール一覧の取得に失敗しました"})
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

// Create inserts a new FIM rule (admin only).
// POST /api/v1/fim-rules
func (h *FIMHandler) Create(c *gin.Context) {
	var req fimRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateFIMRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.CreateFIMRuleInput{
		Name:            req.Name,
		Path:            req.Path,
		Recursive:       req.Recursive,
		ExcludePatterns: req.ExcludePatterns,
		Enabled:         req.Enabled,
		Severity:        req.Severity,
	}

	rule, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FIMルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update replaces an existing FIM rule (admin only).
// PUT /api/v1/fim-rules/:id
func (h *FIMHandler) Update(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "FIMルールが見つかりません"})
		return
	}

	// Pre-populate request with existing values so partial payloads work.
	req := fimRuleRequest{
		Name:            existing.Name,
		Path:            existing.Path,
		Recursive:       existing.Recursive,
		ExcludePatterns: existing.ExcludePatterns,
		Enabled:         existing.Enabled,
		Severity:        existing.Severity,
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateFIMRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.UpdateFIMRuleInput{
		Name:            req.Name,
		Path:            req.Path,
		Recursive:       req.Recursive,
		ExcludePatterns: req.ExcludePatterns,
		Enabled:         req.Enabled,
		Severity:        req.Severity,
	}

	rule, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FIMルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes a FIM rule by ID (admin only).
// DELETE /api/v1/fim-rules/:id
func (h *FIMHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "FIMルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FIMルールの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "FIMルールを削除しました"})
}

// Toggle flips the enabled state of a FIM rule (admin only).
// PATCH /api/v1/fim-rules/:id/toggle
func (h *FIMHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "FIMルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FIMルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}
