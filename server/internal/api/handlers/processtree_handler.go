package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/processtree"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProcessTreeHandler handles process tree API endpoints.
type ProcessTreeHandler struct {
	builder *processtree.Builder
}

// NewProcessTreeHandler creates a new ProcessTreeHandler.
func NewProcessTreeHandler(pool *pgxpool.Pool) *ProcessTreeHandler {
	return &ProcessTreeHandler{builder: processtree.NewBuilder(pool)}
}

// flatProcess is the format the frontend expects.
type flatProcess struct {
	ID          string `json:"id"`
	PID         string `json:"pid"`
	PPID        string `json:"ppid"`
	Image       string `json:"image"`
	CmdLine     string `json:"cmdline"`
	Username    string `json:"username"`
	ParentImage string `json:"parent_image"`
	Timestamp   string `json:"timestamp"`
	Suspicious  bool   `json:"suspicious"`
	MITRETech   string `json:"mitre_tech,omitempty"`
}

// flattenNodes recursively flattens the process tree into a list.
func flattenNodes(nodes []*processtree.ProcessNode, out *[]flatProcess) {
	for _, n := range nodes {
		*out = append(*out, flatProcess{
			ID:          n.EventID,
			PID:         strconv.Itoa(n.PID),
			PPID:        strconv.Itoa(n.PPID),
			Image:       n.Name,
			CmdLine:     n.CmdLine,
			Username:    n.Username,
			ParentImage: n.ParentName,
			Timestamp:   n.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			Suspicious:  n.Suspicious,
			MITRETech:   n.MITRETech,
		})
		flattenNodes(n.Children, out)
	}
}

// GetProcessTree handles GET /api/v1/agents/:id/process-tree?hours=4
func (h *ProcessTreeHandler) GetProcessTree(c *gin.Context) {
	agentID := c.Param("id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}

	tree, err := h.builder.BuildTree(c.Request.Context(), agentID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスツリーの構築に失敗しました"})
		return
	}

	var processes []flatProcess
	flattenNodes(tree.Roots, &processes)
	if processes == nil {
		processes = []flatProcess{}
	}

	c.JSON(http.StatusOK, gin.H{
		"processes": processes,
		"total":     len(processes),
	})
}

// SearchProcesses handles GET /api/v1/agents/:id/process-tree/search?name=powershell&hours=24
func (h *ProcessTreeHandler) SearchProcesses(c *gin.Context) {
	agentID := c.Param("id")
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name パラメータが必要です"})
		return
	}
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}

	nodes, err := h.builder.SearchProcesses(c.Request.Context(), agentID, name, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセス検索に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": nodes, "total": len(nodes)})
}

// GetSuspiciousProcesses handles GET /api/v1/admin/process-tree/suspicious?hours=24
func (h *ProcessTreeHandler) GetSuspiciousProcesses(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}

	nodes, err := h.builder.SearchSuspiciousAllAgents(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "不審なプロセスの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": nodes, "total": len(nodes), "hours": hours})
}
