package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// VulnHandler manages vulnerability CRUD endpoints.
type VulnHandler struct {
	Store *store.VulnStore
}

func NewVulnHandler(s *store.VulnStore) *VulnHandler {
	return &VulnHandler{Store: s}
}

// List returns vulnerabilities with optional filtering.
// GET /api/v1/vulnerabilities
func (h *VulnHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	f := store.VulnFilter{
		AgentID:  c.Query("agent_id"),
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
		Search:   c.Query("search"),
		Limit:    limit,
		Offset:   offset,
	}

	vulns, total, err := h.Store.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "脆弱性一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": vulns, "total": total, "page": page, "per_page": limit})
}

// Stats returns open vulnerability counts by severity.
// GET /api/v1/vulnerabilities/stats
func (h *VulnHandler) Stats(c *gin.Context) {
	stats, err := h.Store.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "統計の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// Create adds a new vulnerability record.
// POST /api/v1/vulnerabilities
func (h *VulnHandler) Create(c *gin.Context) {
	var req struct {
		AgentID         *string  `json:"agent_id"`
		CVEID           string   `json:"cve_id"          binding:"required"`
		Title           string   `json:"title"           binding:"required"`
		Description     string   `json:"description"`
		Severity        string   `json:"severity"        binding:"required"`
		CVSSScore       *float64 `json:"cvss_score"`
		AffectedPackage string   `json:"affected_package"`
		AffectedVersion string   `json:"affected_version"`
		FixedVersion    string   `json:"fixed_version"`
		Status          string   `json:"status"`
		Notes           string   `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id, title, severity は必須です"})
		return
	}
	if req.Status == "" {
		req.Status = "open"
	}
	validSev := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !validSev[req.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "severity は critical/high/medium/low のいずれかです"})
		return
	}

	v := &store.Vulnerability{
		AgentID:         req.AgentID,
		CVEID:           req.CVEID,
		Title:           req.Title,
		Description:     req.Description,
		Severity:        req.Severity,
		CVSSScore:       req.CVSSScore,
		AffectedPackage: req.AffectedPackage,
		AffectedVersion: req.AffectedVersion,
		FixedVersion:    req.FixedVersion,
		Status:          req.Status,
		Notes:           req.Notes,
	}
	id, err := h.Store.Insert(c.Request.Context(), v)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "脆弱性の登録に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "脆弱性を登録しました", "id": id})
}

// Get returns a single vulnerability by ID.
// GET /api/v1/vulnerabilities/:id
func (h *VulnHandler) Get(c *gin.Context) {
	id := c.Param("id")
	v, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "脆弱性が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, v)
}

// UpdateStatus changes the status (and optional notes) of a vulnerability.
// PUT /api/v1/vulnerabilities/:id/status
func (h *VulnHandler) UpdateStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status は必須です"})
		return
	}
	if err := h.Store.UpdateStatus(c.Request.Context(), id, req.Status, req.Notes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータスの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ステータスを更新しました", "id": id, "status": req.Status})
}

// Delete removes a vulnerability record.
// DELETE /api/v1/vulnerabilities/:id
func (h *VulnHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "脆弱性が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "脆弱性を削除しました", "id": id})
}
