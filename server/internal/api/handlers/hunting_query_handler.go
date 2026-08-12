package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/hunting"
	"github.com/gin-gonic/gin"
)

// HuntingQueryHandler provides the threat hunting query API.
type HuntingQueryHandler struct {
	engine *hunting.Engine
}

// NewHuntingQueryHandler creates a new HuntingQueryHandler.
func NewHuntingQueryHandler(engine *hunting.Engine) *HuntingQueryHandler {
	return &HuntingQueryHandler{engine: engine}
}

// Execute handles POST /api/v1/admin/hunting/query
// Runs an ad-hoc threat hunting query against event data.
func (h *HuntingQueryHandler) Execute(c *gin.Context) {
	var q hunting.HuntingQuery
	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query: " + err.Error()})
		return
	}

	// Default time range
	if q.TimeRange.Last == "" && q.TimeRange.Start == "" {
		q.TimeRange.Last = "24h"
	}

	result, err := h.engine.Execute(c.Request.Context(), &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, result)
}

// QuickSearch handles GET /api/v1/admin/hunting/search?q=TERM&type=process&last=24h
func (h *HuntingQueryHandler) QuickSearch(c *gin.Context) {
	term := c.Query("q")
	eventType := c.Query("type")
	last := c.DefaultQuery("last", "24h")

	q := &hunting.HuntingQuery{
		TimeRange: hunting.TimeRange{Last: last},
		Limit:     50,
	}

	if eventType != "" {
		q.EventTypes = []string{eventType}
	}

	if term != "" {
		// Search across common fields
		q.Filters = []hunting.QueryFilter{
			{Field: "process_name", Operator: "contains", Value: term},
		}
	}

	result, err := h.engine.Execute(c.Request.Context(), q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, result)
}

// SavedQueries returns built-in saved hunting queries.
func (h *HuntingQueryHandler) SavedQueries(c *gin.Context) {
	saved := []gin.H{
		{
			"id":          "hunt-001",
			"name":        "Suspicious PowerShell Execution",
			"description": "Find PowerShell processes with encoded commands or unusual flags",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"process"},
				Filters: []hunting.QueryFilter{
					{Field: "process_name", Operator: "contains", Value: "powershell"},
					{Field: "cmdline", Operator: "contains", Value: "-enc"},
				},
				TimeRange: hunting.TimeRange{Last: "24h"},
				Limit:     100,
			},
		},
		{
			"id":          "hunt-002",
			"name":        "Outbound Connections to Unusual Ports",
			"description": "Network connections to non-standard ports (not 80/443/22/3389)",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"network"},
				TimeRange:  hunting.TimeRange{Last: "24h"},
				Limit:      100,
			},
		},
		{
			"id":          "hunt-003",
			"name":        "System File Modifications",
			"description": "File writes to sensitive system paths",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"file"},
				Filters: []hunting.QueryFilter{
					{Field: "file_path", Operator: "contains", Value: "System32"},
				},
				TimeRange: hunting.TimeRange{Last: "24h"},
				Limit:     100,
			},
		},
		{
			"id":          "hunt-004",
			"name":        "DNS Queries to Suspicious Domains",
			"description": "DNS lookups that may indicate C2 communication",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"dns"},
				TimeRange:  hunting.TimeRange{Last: "24h"},
				Limit:      100,
			},
		},
		{
			"id":          "hunt-005",
			"name":        "Failed Authentication Attempts",
			"description": "Authentication failures that may indicate brute force",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"auth"},
				Filters: []hunting.QueryFilter{
					{Field: "username", Operator: "contains", Value: "admin"},
				},
				TimeRange: hunting.TimeRange{Last: "1h"},
				Limit:     100,
			},
		},
		{
			"id":          "hunt-006",
			"name":        "Mimikatz and Credential Tools",
			"description": "Processes matching known credential dumping tool names",
			"query": hunting.HuntingQuery{
				EventTypes: []string{"process"},
				Filters: []hunting.QueryFilter{
					{Field: "process_name", Operator: "contains", Value: "mimikatz"},
				},
				TimeRange: hunting.TimeRange{Last: "7d"},
				Limit:     100,
			},
		},
	}
	c.JSON(http.StatusOK, gin.H{"queries": saved})
}
