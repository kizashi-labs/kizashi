package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	auditpkg "github.com/edr-platform/server/internal/audit"
	"github.com/gin-gonic/gin"
)

// AuditHandler handles structured audit log endpoints.
type AuditHandler struct {
	logger *auditpkg.Logger
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(logger *auditpkg.Logger) *AuditHandler {
	return &AuditHandler{logger: logger}
}

// ListEvents handles GET /api/v1/admin/audit/events.
// Supports: ?user_id=&action=&resource=&start=&end=&limit=50&offset=0
func (h *AuditHandler) ListEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filter := auditpkg.AuditFilter{
		UserID:    c.Query("user_id"),
		Action:    c.Query("action"),
		Resource:  c.Query("resource"),
		StartTime: c.Query("start"),
		EndTime:   c.Query("end"),
		OrgID:     c.Query("org_id"),
		Limit:     limit,
		Offset:    offset,
	}

	events, total, err := h.logger.Query(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query audit events"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetStats handles GET /api/v1/admin/audit/stats.
func (h *AuditHandler) GetStats(c *gin.Context) {
	orgID := c.Query("org_id")
	if orgID == "" {
		if v, exists := c.Get("org_id"); exists {
			orgID, _ = v.(string)
		}
	}
	stats, err := h.logger.GetStats(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit stats"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// ExportCSV handles GET /api/v1/admin/audit/export.
// Returns a CSV download with the same filters as ListEvents.
func (h *AuditHandler) ExportCSV(c *gin.Context) {
	filter := auditpkg.AuditFilter{
		UserID:    c.Query("user_id"),
		Action:    c.Query("action"),
		Resource:  c.Query("resource"),
		StartTime: c.Query("start"),
		EndTime:   c.Query("end"),
		OrgID:     c.Query("org_id"),
		Limit:     10000,
	}

	data, err := h.logger.ExportCSV(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export audit log"})
		return
	}

	filename := fmt.Sprintf("audit_export_%s.csv", time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "text/csv")
	c.Data(http.StatusOK, "text/csv", data)
}
