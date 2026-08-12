package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/siem"
	"github.com/gin-gonic/gin"
)

// SIEMWebhookHandler provides HTTP endpoints for managing webhook-based SIEM integrations
// (Splunk HEC, QRadar, Elastic, Generic webhook).
type SIEMWebhookHandler struct {
	connector *siem.Connector
}

// NewSIEMWebhookHandler creates a handler backed by the given Connector.
func NewSIEMWebhookHandler(connector *siem.Connector) *SIEMWebhookHandler {
	return &SIEMWebhookHandler{connector: connector}
}

type createSIEMWebhookConfigRequest struct {
	Name      string `json:"name" binding:"required"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	IndexName string `json:"index_name"`
	Enabled   *bool  `json:"enabled"`
	Format    string `json:"format"`
	BatchSize int    `json:"batch_size"`
}

// ListConfigs handles GET /api/v1/admin/siem/configs
func (h *SIEMWebhookHandler) ListConfigs(c *gin.Context) {
	cfgs := h.connector.GetConfigs()
	if cfgs == nil {
		cfgs = []*siem.SIEMConfig{}
	}
	c.JSON(http.StatusOK, gin.H{"configs": cfgs, "total": len(cfgs)})
}

// CreateConfig handles POST /api/v1/admin/siem/configs
func (h *SIEMWebhookHandler) CreateConfig(c *gin.Context) {
	var req createSIEMWebhookConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.Name == "" || req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and url are required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Format == "" {
		req.Format = "json"
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 100
	}
	cfg := &siem.SIEMConfig{
		Name:      req.Name,
		Type:      req.Type,
		URL:       req.URL,
		APIKey:    req.APIKey,
		IndexName: req.IndexName,
		Enabled:   enabled,
		Format:    req.Format,
		BatchSize: req.BatchSize,
	}
	if err := h.connector.AddConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, cfg)
}

// UpdateConfig handles PUT /api/v1/admin/siem/configs/:id
func (h *SIEMWebhookHandler) UpdateConfig(c *gin.Context) {
	id := c.Param("id")
	var req createSIEMWebhookConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Format == "" {
		req.Format = "json"
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 100
	}
	updated := &siem.SIEMConfig{
		Name:      req.Name,
		Type:      req.Type,
		URL:       req.URL,
		APIKey:    req.APIKey,
		IndexName: req.IndexName,
		Enabled:   enabled,
		Format:    req.Format,
		BatchSize: req.BatchSize,
	}
	if err := h.connector.UpdateConfig(id, updated); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// DeleteConfig handles DELETE /api/v1/admin/siem/configs/:id
func (h *SIEMWebhookHandler) DeleteConfig(c *gin.Context) {
	id := c.Param("id")
	if err := h.connector.DeleteConfig(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// TestConfig handles POST /api/v1/admin/siem/configs/:id/test
func (h *SIEMWebhookHandler) TestConfig(c *gin.Context) {
	id := c.Param("id")
	start := time.Now()
	success, msg := h.connector.TestConnector(c.Request.Context(), id)
	latency := time.Since(start).Milliseconds()
	c.JSON(http.StatusOK, gin.H{
		"success":    success,
		"message":    msg,
		"latency_ms": latency,
	})
}

// GetSIEMStats handles GET /api/v1/admin/siem/stats
func (h *SIEMWebhookHandler) GetSIEMStats(c *gin.Context) {
	stats := h.connector.GetStats()
	c.JSON(http.StatusOK, stats)
}
