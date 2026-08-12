package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/threatgraph"
	"github.com/gin-gonic/gin"
)

type ThreatGraphHandler struct {
	graph *threatgraph.Graph
}

func NewThreatGraphHandler(g *threatgraph.Graph) *ThreatGraphHandler {
	return &ThreatGraphHandler{graph: g}
}

// GetStats returns graph statistics
// GET /api/v1/admin/threat-graph/stats
func (h *ThreatGraphHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.graph.Stats())
}

// GetSubGraph returns a subgraph around a root node
// GET /api/v1/admin/threat-graph/subgraph
func (h *ThreatGraphHandler) GetSubGraph(c *gin.Context) {
	rootID := c.Query("root_id")
	if rootID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "root_idが必要です"})
		return
	}
	depthStr := c.DefaultQuery("depth", "3")
	depth := 3
	fmt.Sscanf(depthStr, "%d", &depth)

	q := &threatgraph.GraphQuery{
		RootNodeID: rootID,
		Depth:      depth,
	}
	sub := h.graph.GetSubGraph(q)
	c.JSON(http.StatusOK, sub)
}

// Search searches nodes by label
// GET /api/v1/admin/threat-graph/search
func (h *ThreatGraphHandler) Search(c *gin.Context) {
	q := c.Query("q")
	results := h.graph.SearchNodes(q, 50)
	c.JSON(http.StatusOK, gin.H{"nodes": results, "count": len(results)})
}

// Build triggers graph construction from recent events
// POST /api/v1/admin/threat-graph/build
func (h *ThreatGraphHandler) Build(c *gin.Context) {
	agentID := c.DefaultQuery("agent_id", "")
	since := time.Now().Add(-24 * time.Hour)

	if err := h.graph.BuildFromEvents(c.Request.Context(), agentID, since); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "グラフを構築しました",
		"stats":   h.graph.Stats(),
	})
}
