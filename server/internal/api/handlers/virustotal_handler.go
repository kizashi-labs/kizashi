package handlers

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/intel"
	"github.com/gin-gonic/gin"
)

// VirusTotalHandler wraps VT lookups for the API.
type VirusTotalHandler struct {
	Client *intel.VirusTotalClient
}

// NewVirusTotalHandler creates a new VirusTotalHandler.
func NewVirusTotalHandler(apiKey string) *VirusTotalHandler {
	return &VirusTotalHandler{Client: intel.NewVirusTotalClient(apiKey)}
}

// Lookup performs a VirusTotal lookup by IOC value.
// POST /api/v1/intel/vt/lookup
// Body: {"value": "abc123...", "type": "hash|ip|domain"}
func (h *VirusTotalHandler) Lookup(c *gin.Context) {
	if !h.Client.IsConfigured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "VirusTotal APIキーが設定されていません"})
		return
	}

	var req struct {
		Value string `json:"value" binding:"required"`
		Type  string `json:"type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valueフィールドが必要です"})
		return
	}

	iocType := req.Type
	if iocType == "" {
		iocType = vtDetectIOCType(req.Value)
	}

	ctx := c.Request.Context()
	var result *intel.VTResult
	var err error

	switch iocType {
	case "hash":
		result, err = h.Client.LookupHash(ctx, req.Value)
	case "ip":
		result, err = h.Client.LookupIP(ctx, req.Value)
	case "domain":
		result, err = h.Client.LookupDomain(ctx, req.Value)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "サポートされていないIOCタイプ: " + iocType})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "VirusTotal照会に失敗しました: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// vtDetectIOCType infers the IOC type from its value (VT-specific wrapper).
func vtDetectIOCType(value string) string {
	return detectIOCType(strings.TrimSpace(value))
}
