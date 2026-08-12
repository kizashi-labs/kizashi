package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// ReportScheduleHandler provides scheduled report endpoints.
type ReportScheduleHandler struct {
	Store *store.ReportScheduleStore
}

func NewReportScheduleHandler(s *store.ReportScheduleStore) *ReportScheduleHandler {
	return &ReportScheduleHandler{Store: s}
}

// List returns all report schedules.
// GET /api/v1/reports/schedules
func (h *ReportScheduleHandler) List(c *gin.Context) {
	schedules, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": schedules, "total": len(schedules)})
}

// Create adds a new report schedule.
// POST /api/v1/reports/schedules
func (h *ReportScheduleHandler) Create(c *gin.Context) {
	var req struct {
		Name       string   `json:"name"        binding:"required"`
		ReportType string   `json:"report_type" binding:"required"`
		Frequency  string   `json:"frequency"   binding:"required"`
		DayOfWeek  *int     `json:"day_of_week"`
		DayOfMonth *int     `json:"day_of_month"`
		Hour       int      `json:"hour"`
		Recipients []string `json:"recipients"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, report_type, frequency は必須です"})
		return
	}
	if req.Frequency != "daily" && req.Frequency != "weekly" && req.Frequency != "monthly" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "frequency は daily/weekly/monthly のいずれかです"})
		return
	}
	if req.Hour < 0 || req.Hour > 23 {
		req.Hour = 8
	}
	if req.Recipients == nil {
		req.Recipients = []string{}
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	sc := &store.ReportSchedule{
		Name:       req.Name,
		ReportType: req.ReportType,
		Frequency:  req.Frequency,
		DayOfWeek:  req.DayOfWeek,
		DayOfMonth: req.DayOfMonth,
		Hour:       req.Hour,
		Recipients: req.Recipients,
		IsActive:   true,
		CreatedBy:  &uid,
	}
	sc.NextRunAt = store.ComputeNextRun(sc, time.Now().UTC())

	id, err := h.Store.Insert(c.Request.Context(), sc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "スケジュールを作成しました", "id": id})
}

// Update replaces a report schedule.
// PUT /api/v1/reports/schedules/:id
func (h *ReportScheduleHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name       string   `json:"name"        binding:"required"`
		ReportType string   `json:"report_type" binding:"required"`
		Frequency  string   `json:"frequency"   binding:"required"`
		DayOfWeek  *int     `json:"day_of_week"`
		DayOfMonth *int     `json:"day_of_month"`
		Hour       int      `json:"hour"`
		Recipients []string `json:"recipients"`
		IsActive   bool     `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if req.Recipients == nil {
		req.Recipients = []string{}
	}
	sc := &store.ReportSchedule{
		ID:         id,
		Name:       req.Name,
		ReportType: req.ReportType,
		Frequency:  req.Frequency,
		DayOfWeek:  req.DayOfWeek,
		DayOfMonth: req.DayOfMonth,
		Hour:       req.Hour,
		Recipients: req.Recipients,
		IsActive:   req.IsActive,
	}
	sc.NextRunAt = store.ComputeNextRun(sc, time.Now().UTC())

	if err := h.Store.Update(c.Request.Context(), sc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを更新しました", "id": id})
}

// Delete removes a report schedule.
// DELETE /api/v1/reports/schedules/:id
func (h *ReportScheduleHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "スケジュールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを削除しました", "id": id})
}

// Toggle enables or disables a schedule.
// PUT /api/v1/reports/schedules/:id/toggle
func (h *ReportScheduleHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if err := h.Store.SetActive(c.Request.Context(), id, req.IsActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを更新しました", "id": id, "is_active": req.IsActive})
}
