package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/reports"
	"github.com/gin-gonic/gin"
)

// ReportGeneratorHandler provides endpoints for on-demand structured report generation.
// This is separate from the existing ReportHandler which manages DB-persisted report jobs.
type ReportGeneratorHandler struct {
	generator *reports.Generator
}

// NewReportGeneratorHandler creates a new ReportGeneratorHandler.
func NewReportGeneratorHandler(generator *reports.Generator) *ReportGeneratorHandler {
	return &ReportGeneratorHandler{generator: generator}
}

// GenerateReport generates a report synchronously (max 5s timeout).
// POST /api/v1/admin/reports/generate
func (h *ReportGeneratorHandler) GenerateReport(c *gin.Context) {
	var req struct {
		Type      string            `json:"type"      binding:"required"`
		Title     string            `json:"title"`
		DateRange reports.DateRange `json:"date_range"`
		Filters   map[string]string `json:"filters"`
		Format    string            `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title == "" {
		req.Title = titleForType(req.Type)
	}
	if req.Format == "" {
		req.Format = "json"
	}

	// Default date range: last 30 days
	if req.DateRange.End.IsZero() {
		req.DateRange.End = time.Now().UTC()
	}
	if req.DateRange.Start.IsZero() {
		req.DateRange.Start = req.DateRange.End.AddDate(0, 0, -30)
	}

	spec := &reports.ReportSpec{
		Type:        req.Type,
		Title:       req.Title,
		DateRange:   req.DateRange,
		Filters:     req.Filters,
		Format:      req.Format,
		RequestedBy: userIDFromCtx(c),
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	result, err := h.generator.Generate(ctx, spec)
	if err != nil {
		slog.Warn("report_generator: generation failed", "type", req.Type, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to generate report: %v", err)})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListTemplates returns all available report templates.
// GET /api/v1/admin/reports/templates
func (h *ReportGeneratorHandler) ListTemplates(c *gin.Context) {
	templates := reports.GetTemplates()
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

// ExportReport generates a report and returns it as a downloadable attachment.
// POST /api/v1/admin/reports/export
func (h *ReportGeneratorHandler) ExportReport(c *gin.Context) {
	var req struct {
		Type      string            `json:"type"      binding:"required"`
		Title     string            `json:"title"`
		DateRange reports.DateRange `json:"date_range"`
		Filters   map[string]string `json:"filters"`
		Format    string            `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title == "" {
		req.Title = titleForType(req.Type)
	}
	if req.Format == "" {
		req.Format = "json"
	}

	if req.DateRange.End.IsZero() {
		req.DateRange.End = time.Now().UTC()
	}
	if req.DateRange.Start.IsZero() {
		req.DateRange.Start = req.DateRange.End.AddDate(0, 0, -30)
	}

	spec := &reports.ReportSpec{
		Type:        req.Type,
		Title:       req.Title,
		DateRange:   req.DateRange,
		Filters:     req.Filters,
		Format:      req.Format,
		RequestedBy: userIDFromCtx(c),
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	result, err := h.generator.Generate(ctx, spec)
	if err != nil {
		slog.Warn("report_generator: export failed", "type", req.Type, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to generate report: %v", err)})
		return
	}

	filename := fmt.Sprintf("report_%s_%s.%s", req.Type,
		time.Now().Format("20060102"), req.Format)
	c.Header("Content-Disposition", "attachment; filename="+filename)

	if req.Format == "csv" {
		csvBytes, err := h.generator.ToCSV(result.Data)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to convert to CSV"})
			return
		}
		c.Header("Content-Type", "text/csv")
		c.Data(http.StatusOK, "text/csv", csvBytes)
		return
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, result)
}

// titleForType returns a default title for a given report type.
func titleForType(reportType string) string {
	switch reportType {
	case "executive_summary":
		return "Executive Security Summary"
	case "compliance_report":
		return "Compliance Status Report"
	case "incident_report":
		return "Incident Report"
	case "threat_summary":
		return "Threat Intelligence Summary"
	default:
		return "Security Report"
	}
}

// userIDFromCtx extracts the user ID from the gin context.
func userIDFromCtx(c *gin.Context) string {
	userID, _ := c.Get("user_id")
	if s, ok := userID.(string); ok {
		return s
	}
	return ""
}
