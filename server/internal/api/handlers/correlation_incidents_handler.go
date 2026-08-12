package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/correlation"
	"github.com/gin-gonic/gin"
)

// CorrelationIncidentsHandler provides incident management and correlation rule
// endpoints backed by the in-memory correlation.Engine with optional DB persistence.
type CorrelationIncidentsHandler struct {
	engine *correlation.Engine
}

// NewCorrelationIncidentsHandler creates a new CorrelationIncidentsHandler.
func NewCorrelationIncidentsHandler(engine *correlation.Engine) *CorrelationIncidentsHandler {
	return &CorrelationIncidentsHandler{engine: engine}
}

// ListCorrelatedIncidents returns a paginated list of correlated incidents.
// GET /api/v1/admin/incidents?limit=20&offset=0&status=open
func (h *CorrelationIncidentsHandler) ListCorrelatedIncidents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	statusFilter := c.Query("status")

	if limit <= 0 || limit > 200 {
		limit = 20
	}

	incidents, err := h.engine.GetIncidents(c.Request.Context(), limit+offset+1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch incidents"})
		return
	}

	// Apply status filter
	var filtered []*correlation.Incident
	for _, inc := range incidents {
		if statusFilter != "" && inc.Status != statusFilter {
			continue
		}
		filtered = append(filtered, inc)
	}

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	c.JSON(http.StatusOK, gin.H{
		"incidents": page,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"has_more":  end < total,
	})
}

// GetCorrelatedIncident returns detail of a single correlated incident.
// GET /api/v1/admin/incidents/:id
func (h *CorrelationIncidentsHandler) GetCorrelatedIncident(c *gin.Context) {
	id := c.Param("id")
	inc, ok := h.engine.GetIncidentByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "incident not found"})
		return
	}
	c.JSON(http.StatusOK, inc)
}

// UpdateCorrelatedIncidentStatus updates the status of a correlated incident.
// PUT /api/v1/admin/incidents/:id/status
func (h *CorrelationIncidentsHandler) UpdateCorrelatedIncidentStatus(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	allowed := map[string]bool{
		"open": true, "investigating": true, "resolved": true, "closed": true,
	}
	if !allowed[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "status must be one of: open, investigating, resolved, closed",
		})
		return
	}

	h.engine.UpdateIncidentStatus(id, req.Status)
	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"status":  req.Status,
		"message": "incident status updated",
	})
}

// ListCorrelationEngineRules returns all in-memory correlation rules.
// GET /api/v1/admin/correlation/rules
func (h *CorrelationIncidentsHandler) ListCorrelationEngineRules(c *gin.Context) {
	rules := h.engine.ListRules()

	type ruleResponse struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		EventTypes  []string `json:"event_types"`
		TimeWindow  string   `json:"time_window"`
		MinEvents   int      `json:"min_events"`
		Severity    int      `json:"severity"`
		MITRETactic string   `json:"mitre_tactic"`
		MITRETech   string   `json:"mitre_tech"`
	}

	out := make([]ruleResponse, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleResponse{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			EventTypes:  r.EventTypes,
			TimeWindow:  r.TimeWindow.String(),
			MinEvents:   r.MinEvents,
			Severity:    r.Severity,
			MITRETactic: r.MITRETactic,
			MITRETech:   r.MITRETech,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": out,
		"total": len(out),
	})
}

// GetCorrelationEngineStats returns correlation engine aggregate statistics.
// GET /api/v1/admin/correlation/stats
func (h *CorrelationIncidentsHandler) GetCorrelationEngineStats(c *gin.Context) {
	stats := h.engine.GetStats()
	c.JSON(http.StatusOK, stats)
}
