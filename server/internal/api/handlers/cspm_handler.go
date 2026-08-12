package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/cspm"
	"github.com/gin-gonic/gin"
)

type CSPMHandler struct {
	checker *cspm.Checker
}

func NewCSPMHandler(checker *cspm.Checker) *CSPMHandler {
	return &CSPMHandler{checker: checker}
}

// Scan runs a CSPM scan
// POST /api/v1/admin/cspm/scan
func (h *CSPMHandler) Scan(c *gin.Context) {
	var cfg cspm.ProviderConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		// Use simulated default config
		cfg = cspm.ProviderConfig{
			Provider:  cspm.ProviderAWS,
			AccountID: "123456789012",
			Region:    "ap-northeast-1",
			Settings: map[string]interface{}{
				"s3_block_public_access": true,
				"root_mfa_enabled":       false,
				"cloudtrail_enabled":     true,
				"ssh_unrestricted":       true,
				"ebs_encryption":         false,
			},
		}
	}
	if len(cfg.Settings) == 0 {
		cfg.Settings = map[string]interface{}{
			"s3_block_public_access": true,
			"root_mfa_enabled":       false,
			"cloudtrail_enabled":     true,
			"ssh_unrestricted":       true,
			"ebs_encryption":         false,
		}
	}

	result, err := h.checker.Scan(c.Request.Context(), cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetLastScans returns last scan results for all providers
// GET /api/v1/admin/cspm/scans
func (h *CSPMHandler) GetLastScans(c *gin.Context) {
	provider := c.Query("provider")
	if provider != "" {
		result := h.checker.GetLastScan(provider)
		if result == nil {
			c.JSON(http.StatusOK, gin.H{"message": "スキャン結果がありません"})
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}
	results := h.checker.GetAllLastScans()
	c.JSON(http.StatusOK, gin.H{"scans": results, "count": len(results)})
}
