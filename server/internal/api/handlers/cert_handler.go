package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/cert"
	"github.com/gin-gonic/gin"
)

// CertHandler handles mTLS certificate enrollment for agents.
type CertHandler struct {
	ca *cert.CAManager
}

// NewCertHandler creates a new CertHandler.
func NewCertHandler(ca *cert.CAManager) *CertHandler {
	return &CertHandler{ca: ca}
}

// GetCA handles GET /api/v1/agents/:id/cert/ca
// Returns the CA certificate PEM. Public — no auth required for agent bootstrap.
func (h *CertHandler) GetCA(c *gin.Context) {
	if h.ca == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "CA証明書マネージャが初期化されていません"})
		return
	}
	c.Data(http.StatusOK, "application/x-pem-file", h.ca.CAPem())
}

// Enroll handles POST /api/v1/agents/:id/cert/enroll
// Accepts a CSR, signs it, and returns the signed agent certificate.
// Requires valid JWT or enrollment token (handled by router middleware).
func (h *CertHandler) Enroll(c *gin.Context) {
	if h.ca == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "CA証明書マネージャが初期化されていません"})
		return
	}

	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "エージェントIDが必要です"})
		return
	}

	var req struct {
		CSRPEM string `json:"csr_pem" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "csr_pemフィールドが必要です"})
		return
	}

	certPEM, err := h.ca.SignAgent([]byte(req.CSRPEM), agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSRの署名に失敗しました: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cert_pem": string(certPEM),
	})
}
