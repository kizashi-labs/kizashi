package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/reports"
	"github.com/gin-gonic/gin"
)

// AdminReportSchedulesHandler handles admin scheduled report CRUD endpoints.
// Routes: /api/v1/admin/reports/schedules
type AdminReportSchedulesHandler struct {
	scheduler *reports.Scheduler
}

// NewAdminReportSchedulesHandler creates a new handler.
func NewAdminReportSchedulesHandler(scheduler *reports.Scheduler) *AdminReportSchedulesHandler {
	return &AdminReportSchedulesHandler{scheduler: scheduler}
}

// List handles GET /api/v1/admin/reports/schedules
func (h *AdminReportSchedulesHandler) List(c *gin.Context) {
	schedules, err := h.scheduler.ListSchedules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"schedules": schedules, "total": len(schedules)})
}

// Create handles POST /api/v1/admin/reports/schedules
func (h *AdminReportSchedulesHandler) Create(c *gin.Context) {
	var report reports.ScheduledReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if report.Name == "" || report.ReportType == "" || report.Schedule == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, report_type, schedule は必須です"})
		return
	}
	if err := h.scheduler.AddSchedule(c.Request.Context(), &report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "スケジュールを作成しました", "id": report.ID, "next_run": report.NextRun})
}

// Update handles PUT /api/v1/admin/reports/schedules/:id
func (h *AdminReportSchedulesHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var report reports.ScheduledReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	report.ID = id
	if err := h.scheduler.UpdateSchedule(c.Request.Context(), &report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを更新しました", "id": id})
}

// Delete handles DELETE /api/v1/admin/reports/schedules/:id
func (h *AdminReportSchedulesHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.scheduler.RemoveSchedule(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "スケジュールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを削除しました", "id": id})
}

// Toggle handles PUT /api/v1/admin/reports/schedules/:id/toggle
func (h *AdminReportSchedulesHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.scheduler.ToggleSchedule(c.Request.Context(), id, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを更新しました", "id": id, "enabled": req.Enabled})
}
