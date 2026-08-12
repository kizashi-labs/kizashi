package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/deception"
	"github.com/gin-gonic/gin"
)

type DeceptionMgrHandler struct {
	manager *deception.Manager
}

func NewDeceptionMgrHandler(manager *deception.Manager) *DeceptionMgrHandler {
	return &DeceptionMgrHandler{manager: manager}
}

// GetTokens returns all deception tokens
// GET /api/v1/admin/deception/tokens
func (h *DeceptionMgrHandler) GetTokens(c *gin.Context) {
	tokens := h.manager.GetTokens()
	c.JSON(http.StatusOK, gin.H{"tokens": tokens, "count": len(tokens)})
}

// CreateToken creates a new deception token
// POST /api/v1/admin/deception/tokens
func (h *DeceptionMgrHandler) CreateToken(c *gin.Context) {
	var req struct {
		Type        string `json:"type"`
		Name        string `json:"name"        binding:"required"`
		Description string `json:"description"`
		Path        string `json:"path"`
		AgentID     string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameが必要です"})
		return
	}

	tokenType := deception.TokenType(req.Type)
	if tokenType == "" {
		tokenType = deception.TokenCanaryFile
	}

	t, err := h.manager.CreateToken(tokenType, req.Name, req.Description, req.Path, req.AgentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, t)
}

// DeleteToken removes a deception token
// DELETE /api/v1/admin/deception/tokens/:id
func (h *DeceptionMgrHandler) DeleteToken(c *gin.Context) {
	id := c.Param("id")
	if !h.manager.DeleteToken(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "トークンが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "トークンを削除しました"})
}

// TriggerToken simulates a token being accessed
// POST /api/v1/admin/deception/tokens/:id/trigger
func (h *DeceptionMgrHandler) TriggerToken(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		SourceIP    string `json:"source_ip"`
		ProcessName string `json:"process_name"`
		ProcessID   int    `json:"process_id"`
		AgentID     string `json:"agent_id"`
	}
	_ = c.ShouldBindJSON(&req)

	alert, err := h.manager.Trigger(id, req.SourceIP, req.ProcessName, req.ProcessID, req.AgentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, alert)
}

// GetAlerts returns recent deception alerts
// GET /api/v1/admin/deception/alerts
func (h *DeceptionMgrHandler) GetAlerts(c *gin.Context) {
	alerts := h.manager.GetAlerts(100)
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "count": len(alerts)})
}

// GetStats returns deception statistics
// GET /api/v1/admin/deception/stats
func (h *DeceptionMgrHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.manager.Stats())
}
