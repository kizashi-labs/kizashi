package handlers

import (
	"fmt"
	"net/http"

	"github.com/edr-platform/server/internal/xdr"
	"github.com/gin-gonic/gin"
)

type XDRHandler struct {
	engine *xdr.Engine
}

func NewXDRHandler(engine *xdr.Engine) *XDRHandler {
	return &XDRHandler{engine: engine}
}

// GetStats returns XDR engine statistics
// GET /api/v1/admin/xdr/stats
func (h *XDRHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.engine.Stats())
}

// IngestEvent adds an event to the XDR engine
// POST /api/v1/admin/xdr/events
func (h *XDRHandler) IngestEvent(c *gin.Context) {
	var evt xdr.XDREvent
	if err := c.ShouldBindJSON(&evt); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.engine.IngestEvent(evt)
	c.JSON(http.StatusOK, gin.H{"message": "イベントを追加しました"})
}

// Correlate runs cross-domain correlation
// POST /api/v1/admin/xdr/correlate
func (h *XDRHandler) Correlate(c *gin.Context) {
	incidents, err := h.engine.Correlate(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"incidents": incidents,
		"count":     len(incidents),
	})
}

// GetRecentEvents returns recent XDR events
// GET /api/v1/admin/xdr/events
func (h *XDRHandler) GetRecentEvents(c *gin.Context) {
	limit := 100
	fmt.Sscanf(c.DefaultQuery("limit", "100"), "%d", &limit)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	events := h.engine.GetRecentEvents(limit)
	c.JSON(http.StatusOK, gin.H{"events": events, "count": len(events)})
}
