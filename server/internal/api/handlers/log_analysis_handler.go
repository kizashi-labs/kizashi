package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/response"
)

// LogAnalysisHandler handles log parse rules and analysis jobs.
type LogAnalysisHandler struct {
	pool *pgxpool.Pool
}

// NewLogAnalysisHandler creates a new LogAnalysisHandler.
func NewLogAnalysisHandler(pool *pgxpool.Pool) *LogAnalysisHandler {
	return &LogAnalysisHandler{pool: pool}
}

type logParseRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	LogSource   string          `json:"log_source"`
	Pattern     string          `json:"pattern"`
	FieldMap    json.RawMessage `json:"field_map"`
	IsActive    bool            `json:"is_active"`
	Priority    int             `json:"priority"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type logAnalysisJob struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Query       string     `json:"query"`
	TimeRange   string     `json:"time_range"`
	Status      string     `json:"status"`
	ResultCount *int       `json:"result_count,omitempty"`
	ErrorMsg    *string    `json:"error_msg,omitempty"`
	CreatedBy   *string    `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ListParseRules handles GET /api/v1/admin/log-analysis/rules
func (h *LogAnalysisHandler) ListParseRules(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, description, log_source, pattern, field_map, is_active, priority, created_at, updated_at
		FROM log_parse_rules
		ORDER BY priority ASC, created_at DESC
	`)
	if err != nil {
		response.InternalError(c, "failed to list parse rules")
		return
	}
	defer rows.Close()

	var rules []logParseRule
	for rows.Next() {
		var r logParseRule
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.LogSource, &r.Pattern,
			&r.FieldMap, &r.IsActive, &r.Priority, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if rules == nil {
		rules = []logParseRule{}
	}
	response.OK(c, rules)
}

// CreateParseRule handles POST /api/v1/admin/log-analysis/rules
func (h *LogAnalysisHandler) CreateParseRule(c *gin.Context) {
	var req struct {
		Name        string          `json:"name" binding:"required"`
		Description *string         `json:"description"`
		LogSource   string          `json:"log_source" binding:"required"`
		Pattern     string          `json:"pattern" binding:"required"`
		FieldMap    json.RawMessage `json:"field_map"`
		IsActive    *bool           `json:"is_active"`
		Priority    *int            `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if len(req.FieldMap) == 0 {
		req.FieldMap = json.RawMessage("{}")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	priority := 100
	if req.Priority != nil {
		priority = *req.Priority
	}

	id := uuid.New().String()
	var createdAt, updatedAt time.Time
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO log_parse_rules (id, name, description, log_source, pattern, field_map, is_active, priority)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at
	`, id, req.Name, req.Description, req.LogSource, req.Pattern, req.FieldMap, isActive, priority,
	).Scan(&createdAt, &updatedAt)
	if err != nil {
		response.InternalError(c, "failed to create parse rule: "+err.Error())
		return
	}

	response.Created(c, logParseRule{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		LogSource:   req.LogSource,
		Pattern:     req.Pattern,
		FieldMap:    req.FieldMap,
		IsActive:    isActive,
		Priority:    priority,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	})
}

// UpdateParseRule handles PUT /api/v1/admin/log-analysis/rules/:id
func (h *LogAnalysisHandler) UpdateParseRule(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        *string         `json:"name"`
		Description *string         `json:"description"`
		LogSource   *string         `json:"log_source"`
		Pattern     *string         `json:"pattern"`
		FieldMap    json.RawMessage `json:"field_map"`
		IsActive    *bool           `json:"is_active"`
		Priority    *int            `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	res, err := h.pool.Exec(c.Request.Context(), `
		UPDATE log_parse_rules SET
		  name        = COALESCE($2, name),
		  description = COALESCE($3, description),
		  log_source  = COALESCE($4, log_source),
		  pattern     = COALESCE($5, pattern),
		  is_active   = COALESCE($6, is_active),
		  priority    = COALESCE($7, priority),
		  updated_at  = NOW()
		WHERE id = $1
	`, id, req.Name, req.Description, req.LogSource, req.Pattern, req.IsActive, req.Priority)
	if err != nil {
		response.InternalError(c, "failed to update parse rule")
		return
	}
	if res.RowsAffected() == 0 {
		response.NotFound(c, "parse rule not found")
		return
	}
	response.OK(c, gin.H{"message": "rule updated"})
}

// DeleteParseRule handles DELETE /api/v1/admin/log-analysis/rules/:id
func (h *LogAnalysisHandler) DeleteParseRule(c *gin.Context) {
	id := c.Param("id")
	res, err := h.pool.Exec(c.Request.Context(), `DELETE FROM log_parse_rules WHERE id = $1`, id)
	if err != nil {
		response.InternalError(c, "failed to delete parse rule")
		return
	}
	if res.RowsAffected() == 0 {
		response.NotFound(c, "parse rule not found")
		return
	}
	response.NoContent(c)
}

// TestParseRule handles POST /api/v1/admin/log-analysis/rules/:id/test
func (h *LogAnalysisHandler) TestParseRule(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Sample string `json:"sample" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	var pattern string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT pattern FROM log_parse_rules WHERE id = $1`, id,
	).Scan(&pattern)
	if err != nil {
		response.NotFound(c, "parse rule not found")
		return
	}

	// Attempt regex match and return named groups as parsed fields
	parsed := map[string]string{}
	matched := false
	re, reErr := regexp.Compile(pattern)
	if reErr == nil {
		match := re.FindStringSubmatch(req.Sample)
		if match != nil {
			matched = true
			for i, name := range re.SubexpNames() {
				if i != 0 && name != "" && i < len(match) {
					parsed[name] = match[i]
				}
			}
			// If no named groups, expose full match
			if len(parsed) == 0 {
				parsed["match"] = match[0]
			}
		}
	}

	response.OK(c, gin.H{
		"rule_id": id,
		"sample":  req.Sample,
		"matched": matched,
		"fields":  parsed,
	})
}

// ListJobs handles GET /api/v1/admin/log-analysis/jobs
func (h *LogAnalysisHandler) ListJobs(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, query, time_range, status, result_count, error_msg,
		       created_by::text, created_at, completed_at
		FROM log_analysis_jobs
		ORDER BY created_at DESC
		LIMIT 100
	`)
	if err != nil {
		response.InternalError(c, "failed to list jobs")
		return
	}
	defer rows.Close()

	var jobs []logAnalysisJob
	for rows.Next() {
		var j logAnalysisJob
		if err := rows.Scan(
			&j.ID, &j.Name, &j.Query, &j.TimeRange, &j.Status,
			&j.ResultCount, &j.ErrorMsg, &j.CreatedBy, &j.CreatedAt, &j.CompletedAt,
		); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if jobs == nil {
		jobs = []logAnalysisJob{}
	}
	response.OK(c, jobs)
}

// CreateJob handles POST /api/v1/admin/log-analysis/jobs
func (h *LogAnalysisHandler) CreateJob(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		Query     string `json:"query" binding:"required"`
		TimeRange string `json:"time_range"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.TimeRange == "" {
		req.TimeRange = "1h"
	}

	jobID := uuid.New().String()
	var createdAt time.Time
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO log_analysis_jobs (id, name, query, time_range, status)
		VALUES ($1, $2, $3, $4, 'running')
		RETURNING created_at
	`, jobID, req.Name, req.Query, req.TimeRange).Scan(&createdAt)
	if err != nil {
		response.InternalError(c, "failed to create job: "+err.Error())
		return
	}

	// Background: count matching log entries and mark the job completed.
	pool := h.pool
	query := req.Query
	timeRange := req.TimeRange
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Parse time range (e.g. "1h", "24h", "7d") into a PostgreSQL interval.
		interval := "1 hour"
		if len(timeRange) >= 2 {
			num := timeRange[:len(timeRange)-1]
			unit := timeRange[len(timeRange)-1:]
			switch unit {
			case "h":
				interval = num + " hours"
			case "d":
				interval = num + " days"
			case "m":
				interval = num + " minutes"
			}
		}

		// Count matching audit log entries (keyword search in action or details).
		var resultCount int
		var tableExists bool
		if err := pool.QueryRow(bgCtx,
			`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='audit_logs')`).
			Scan(&tableExists); err != nil {
			slog.Warn("log_analysis: audit_logs テーブル確認に失敗しました", "job_id", jobID, "error", err)
		}

		if tableExists {
			if err := pool.QueryRow(bgCtx,
				`SELECT COUNT(*) FROM audit_logs
				 WHERE created_at >= NOW() - $1::interval
				   AND (action ILIKE $2 OR details::text ILIKE $2)`,
				interval, "%"+query+"%",
			).Scan(&resultCount); err != nil {
				slog.Warn("log_analysis: 結果カウントのクエリに失敗しました", "job_id", jobID, "error", err)
			}
		}

		// Use a fresh context for the final status update so it succeeds even if bgCtx timed out.
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer updateCancel()
		if _, err := pool.Exec(updateCtx,
			`UPDATE log_analysis_jobs SET status='completed', result_count=$2, completed_at=NOW() WHERE id=$1`,
			jobID, resultCount); err != nil {
			slog.Warn("log_analysis: ジョブステータスの更新に失敗しました", "job_id", jobID, "error", err)
		}
	}()

	response.Created(c, logAnalysisJob{
		ID:        jobID,
		Name:      req.Name,
		Query:     req.Query,
		TimeRange: req.TimeRange,
		Status:    "running",
		CreatedAt: createdAt,
	})
}

// GetJobResults handles GET /api/v1/admin/log-analysis/jobs/:id
func (h *LogAnalysisHandler) GetJobResults(c *gin.Context) {
	id := c.Param("id")
	var j logAnalysisJob
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, name, query, time_range, status, result_count, error_msg,
		       created_by::text, created_at, completed_at
		FROM log_analysis_jobs
		WHERE id = $1
	`, id).Scan(
		&j.ID, &j.Name, &j.Query, &j.TimeRange, &j.Status,
		&j.ResultCount, &j.ErrorMsg, &j.CreatedBy, &j.CreatedAt, &j.CompletedAt,
	)
	if err != nil {
		response.NotFound(c, "job not found")
		return
	}

	response.OK(c, gin.H{
		"job":     j,
		"results": []gin.H{},
	})
}

// ensure net/http import is used
var _ = http.StatusOK
