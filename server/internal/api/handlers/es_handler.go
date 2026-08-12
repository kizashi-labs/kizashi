package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/shipper"
	"github.com/gin-gonic/gin"
)

type ESHandler struct {
	shipper *shipper.ElasticsearchShipper
}

func NewESHandler(s *shipper.ElasticsearchShipper) *ESHandler {
	return &ESHandler{shipper: s}
}

// Test handles POST /api/v1/admin/elasticsearch/test
func (h *ESHandler) Test(c *gin.Context) {
	status, err := h.shipper.Test(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "success": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "cluster_status": status})
}

// Flush handles POST /api/v1/admin/elasticsearch/flush
func (h *ESHandler) Flush(c *gin.Context) {
	h.shipper.Flush(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"message": "バッファをフラッシュしました"})
}
