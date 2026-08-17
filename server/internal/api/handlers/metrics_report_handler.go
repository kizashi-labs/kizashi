package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MetricsReportHandler manages scheduled report definitions and generated reports.
type MetricsReportHandler struct {
	pool *pgxpool.Pool
}

// NewMetricsReportHandler creates a new MetricsReportHandler.
func NewMetricsReportHandler(pool *pgxpool.Pool) *MetricsReportHandler {
	return &MetricsReportHandler{pool: pool}
}

// toJSON serialises v to a JSON string, returning fallback on nil or error.
func toJSON(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fallback
	}
	return string(b)
}

// ListSchedules GET /schedules
func (h *MetricsReportHandler) ListSchedules(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, report_type, COALESCE(description,''), COALESCE(template_id,''),
		       schedule, recipients, parameters, output_format,
		       is_active, last_run, next_run, run_count, created_at, updated_at
		FROM report_schedules_v2
		ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Schedule struct {
		ID           string          `json:"id"`
		Name         string          `json:"name"`
		ReportType   string          `json:"report_type"`
		Description  string          `json:"description"`
		TemplateID   string          `json:"template_id"`
		Schedule     string          `json:"schedule"`
		Recipients   json.RawMessage `json:"recipients"`
		Parameters   json.RawMessage `json:"parameters"`
		OutputFormat string          `json:"output_format"`
		IsActive     bool            `json:"is_active"`
		LastRun      *time.Time      `json:"last_run"`
		NextRun      *time.Time      `json:"next_run"`
		RunCount     int             `json:"run_count"`
		CreatedAt    time.Time       `json:"created_at"`
		UpdatedAt    time.Time       `json:"updated_at"`
	}

	var schedules []Schedule
	for rows.Next() {
		var s Schedule
		if err := rows.Scan(&s.ID, &s.Name, &s.ReportType, &s.Description, &s.TemplateID,
			&s.Schedule, &s.Recipients, &s.Parameters, &s.OutputFormat,
			&s.IsActive, &s.LastRun, &s.NextRun, &s.RunCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		schedules = append(schedules, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if schedules == nil {
		schedules = []Schedule{}
	}
	c.JSON(http.StatusOK, gin.H{"schedules": schedules})
}

// CreateSchedule POST /schedules
func (h *MetricsReportHandler) CreateSchedule(c *gin.Context) {
	var body struct {
		Name         string         `json:"name" binding:"required"`
		ReportType   string         `json:"report_type" binding:"required"`
		Description  string         `json:"description"`
		TemplateID   string         `json:"template_id"`
		Schedule     string         `json:"schedule" binding:"required"`
		Recipients   []any          `json:"recipients"`
		Parameters   map[string]any `json:"parameters"`
		OutputFormat string         `json:"output_format"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.OutputFormat == "" {
		body.OutputFormat = "pdf"
	}

	recipJSON := toJSON(body.Recipients, "[]")
	paramJSON := toJSON(body.Parameters, "{}")

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO report_schedules_v2
		  (name, report_type, description, template_id, schedule, recipients, parameters, output_format)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)
		RETURNING id`,
		body.Name, body.ReportType, body.Description, body.TemplateID,
		body.Schedule, recipJSON, paramJSON, body.OutputFormat,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "スケジュールを作成しました"})
}

// UpdateSchedule PUT /schedules/:id
func (h *MetricsReportHandler) UpdateSchedule(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Name         string         `json:"name"`
		ReportType   string         `json:"report_type"`
		Description  string         `json:"description"`
		TemplateID   string         `json:"template_id"`
		Schedule     string         `json:"schedule"`
		Recipients   []any          `json:"recipients"`
		Parameters   map[string]any `json:"parameters"`
		OutputFormat string         `json:"output_format"`
		IsActive     *bool          `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	recipJSON := toJSON(body.Recipients, "[]")
	paramJSON := toJSON(body.Parameters, "{}")

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE report_schedules_v2 SET
		  name=COALESCE(NULLIF($1,''), name),
		  report_type=COALESCE(NULLIF($2,''), report_type),
		  description=COALESCE(NULLIF($3,''), description),
		  template_id=COALESCE(NULLIF($4,''), template_id),
		  schedule=COALESCE(NULLIF($5,''), schedule),
		  recipients=$6::jsonb,
		  parameters=$7::jsonb,
		  output_format=COALESCE(NULLIF($8,''), output_format),
		  is_active=COALESCE($9, is_active),
		  updated_at=NOW()
		WHERE id=$10`,
		body.Name, body.ReportType, body.Description, body.TemplateID,
		body.Schedule, recipJSON, paramJSON, body.OutputFormat, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "スケジュールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを更新しました"})
}

// DeleteSchedule DELETE /schedules/:id
func (h *MetricsReportHandler) DeleteSchedule(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM report_schedules_v2 WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "スケジュールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "スケジュールを削除しました"})
}

// ToggleSchedule POST /schedules/:id/toggle
func (h *MetricsReportHandler) ToggleSchedule(c *gin.Context) {
	id := c.Param("id")
	var isActive bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE report_schedules_v2
		SET is_active = NOT is_active, updated_at = NOW()
		WHERE id=$1
		RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "スケジュールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// ListReports GET /reports — filter by report_type, status
func (h *MetricsReportHandler) ListReports(c *gin.Context) {
	reportType := c.Query("report_type")
	status := c.Query("status")

	query := `
		SELECT id, COALESCE(schedule_id::text,''), name, report_type,
		       period_start, period_end, status, file_size_kb,
		       output_format, COALESCE(generated_by::text,''), generated_at, created_at
		FROM generated_reports
		WHERE 1=1`
	args := []interface{}{}
	idx := 1

	if reportType != "" {
		query += fmt.Sprintf(" AND report_type=$%d", idx)
		args = append(args, reportType)
		idx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status=$%d", idx)
		args = append(args, status)
		idx++
	}
	_ = idx
	query += " ORDER BY created_at DESC"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Report struct {
		ID           string     `json:"id"`
		ScheduleID   string     `json:"schedule_id"`
		Name         string     `json:"name"`
		ReportType   string     `json:"report_type"`
		PeriodStart  *time.Time `json:"period_start"`
		PeriodEnd    *time.Time `json:"period_end"`
		Status       string     `json:"status"`
		FileSizeKB   *int       `json:"file_size_kb"`
		OutputFormat string     `json:"output_format"`
		GeneratedBy  string     `json:"generated_by"`
		GeneratedAt  *time.Time `json:"generated_at"`
		CreatedAt    time.Time  `json:"created_at"`
	}

	var reports []Report
	for rows.Next() {
		var r Report
		if err := rows.Scan(&r.ID, &r.ScheduleID, &r.Name, &r.ReportType,
			&r.PeriodStart, &r.PeriodEnd, &r.Status, &r.FileSizeKB,
			&r.OutputFormat, &r.GeneratedBy, &r.GeneratedAt, &r.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		reports = append(reports, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if reports == nil {
		reports = []Report{}
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

// GenerateReport POST /reports/generate
func (h *MetricsReportHandler) GenerateReport(c *gin.Context) {
	var body struct {
		ReportType   string     `json:"report_type" binding:"required"`
		PeriodStart  *time.Time `json:"period_start"`
		PeriodEnd    *time.Time `json:"period_end"`
		OutputFormat string     `json:"output_format"`
		Name         string     `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.OutputFormat == "" {
		body.OutputFormat = "pdf"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO generated_reports
		  (name, report_type, period_start, period_end, status, output_format, generated_by)
		VALUES ($1,$2,$3,$4,'pending',$5,NULLIF($6,'')::uuid)
		RETURNING id`,
		body.Name, body.ReportType, body.PeriodStart, body.PeriodEnd,
		body.OutputFormat, userIDStr,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if _, err := h.pool.Exec(c.Request.Context(), `
			UPDATE generated_reports
			SET status='completed', file_size_kb=0, generated_at=NOW()
			WHERE id=$1`,
		id,
	); !WriteOK(c, err) {
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"id": id, "status": "pending", "message": "レポート生成を開始しました"})
}

// GetReport GET /reports/:id
func (h *MetricsReportHandler) GetReport(c *gin.Context) {
	id := c.Param("id")

	type Report struct {
		ID           string     `json:"id"`
		ScheduleID   string     `json:"schedule_id"`
		Name         string     `json:"name"`
		ReportType   string     `json:"report_type"`
		PeriodStart  *time.Time `json:"period_start"`
		PeriodEnd    *time.Time `json:"period_end"`
		Status       string     `json:"status"`
		FileSizeKB   *int       `json:"file_size_kb"`
		OutputFormat string     `json:"output_format"`
		GeneratedBy  string     `json:"generated_by"`
		GeneratedAt  *time.Time `json:"generated_at"`
		CreatedAt    time.Time  `json:"created_at"`
	}

	var r Report
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, COALESCE(schedule_id::text,''), name, report_type,
		       period_start, period_end, status, file_size_kb,
		       output_format, COALESCE(generated_by::text,''), generated_at, created_at
		FROM generated_reports WHERE id=$1`, id,
	).Scan(&r.ID, &r.ScheduleID, &r.Name, &r.ReportType,
		&r.PeriodStart, &r.PeriodEnd, &r.Status, &r.FileSizeKB,
		&r.OutputFormat, &r.GeneratedBy, &r.GeneratedAt, &r.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// DeleteReport DELETE /reports/:id
func (h *MetricsReportHandler) DeleteReport(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM generated_reports WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "レポートを削除しました"})
}

// GetStats GET /stats — report counts by type, last 30 days generation trend
func (h *MetricsReportHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Counts by type
	rows, err := h.pool.Query(ctx, `
		SELECT report_type,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed,
		       SUM(CASE WHEN status='failed'    THEN 1 ELSE 0 END) AS failed
		FROM generated_reports
		GROUP BY report_type
		ORDER BY report_type`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type TypeStat struct {
		ReportType string `json:"report_type"`
		Total      int    `json:"total"`
		Completed  int    `json:"completed"`
		Failed     int    `json:"failed"`
	}
	var byType []TypeStat
	for rows.Next() {
		var s TypeStat
		if err := rows.Scan(&s.ReportType, &s.Total, &s.Completed, &s.Failed); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		byType = append(byType, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	rows.Close()
	if byType == nil {
		byType = []TypeStat{}
	}

	// Last 30 days trend (daily counts)
	trendRows, err := h.pool.Query(ctx, `
		SELECT DATE(created_at) AS day, COUNT(*) AS count
		FROM generated_reports
		WHERE created_at >= NOW() - INTERVAL '30 days'
		GROUP BY DATE(created_at)
		ORDER BY day`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer trendRows.Close()

	type TrendPoint struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	var trend []TrendPoint
	for trendRows.Next() {
		var tp TrendPoint
		if err := trendRows.Scan(&tp.Day, &tp.Count); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		trend = append(trend, tp)
	}
	if err := trendRows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if trend == nil {
		trend = []TrendPoint{}
	}

	// Active schedule count
	var scheduleCount int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM report_schedules_v2 WHERE is_active=true`).Scan(&scheduleCount)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"by_type":          byType,
		"trend_30d":        trend,
		"active_schedules": scheduleCount,
	})
}
