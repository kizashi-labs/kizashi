package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ForensicsAutomationHandler struct{ pool *pgxpool.Pool }

func NewForensicsAutomationHandler(pool *pgxpool.Pool) *ForensicsAutomationHandler {
	return &ForensicsAutomationHandler{pool: pool}
}

func (h *ForensicsAutomationHandler) ListJobs(c *gin.Context) {
	ctx := c.Request.Context()
	exists := tableIsThere(ctx, h.pool, "forensics_automation_jobs")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"jobs": []interface{}{}, "total": 0})
		return
	}
	rows, err := h.pool.Query(ctx, `SELECT id, name, trigger_type, status, priority, evidence_count, assigned_analyst, started_at, completed_at FROM forensics_automation_jobs ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var jobs []gin.H
	for rows.Next() {
		var id, name, triggerType, status, priority string
		var assignedAnalyst *string
		var evidenceCount int
		var startedAt, completedAt *time.Time
		if err := rows.Scan(&id, &name, &triggerType, &status, &priority, &evidenceCount, &assignedAnalyst, &startedAt, &completedAt); err != nil {
			continue
		}
		job := gin.H{
			"id":               id,
			"name":             name,
			"trigger_type":     triggerType,
			"status":           status,
			"priority":         priority,
			"evidence_count":   evidenceCount,
			"assigned_analyst": assignedAnalyst,
		}
		if startedAt != nil {
			job["started_at"] = startedAt.Format(time.RFC3339)
		}
		if completedAt != nil {
			job["completed_at"] = completedAt.Format(time.RFC3339)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if jobs == nil {
		jobs = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": len(jobs)})
}

func (h *ForensicsAutomationHandler) GetJob(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "forensics_automation_jobs")
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "ジョブが見つかりません"})
		return
	}

	var jobID, name, triggerType, status, priority string
	var assignedAnalyst *string
	var evidenceCount int
	var startedAt, completedAt *time.Time
	err := h.pool.QueryRow(ctx,
		`SELECT id, name, trigger_type, status, priority, evidence_count, assigned_analyst, started_at, completed_at FROM forensics_automation_jobs WHERE id = $1`,
		id,
	).Scan(&jobID, &name, &triggerType, &status, &priority, &evidenceCount, &assignedAnalyst, &startedAt, &completedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ジョブが見つかりません"})
		return
	}

	job := gin.H{
		"id":               jobID,
		"name":             name,
		"trigger_type":     triggerType,
		"status":           status,
		"priority":         priority,
		"evidence_count":   evidenceCount,
		"assigned_analyst": assignedAnalyst,
	}
	if startedAt != nil {
		job["started_at"] = startedAt.Format(time.RFC3339)
	}
	if completedAt != nil {
		job["completed_at"] = completedAt.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, job)
}

func (h *ForensicsAutomationHandler) CreateJob(c *gin.Context) {
	var req struct {
		Name            string `json:"name" binding:"required"`
		TriggerType     string `json:"trigger_type"`
		Priority        string `json:"priority"`
		AssignedAnalyst string `json:"assigned_analyst"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	switch req.TriggerType {
	case "manual", "alert", "schedule", "incident":
	default:
		req.TriggerType = "manual"
	}
	switch req.Priority {
	case "low", "medium", "high", "critical":
	default:
		req.Priority = "medium"
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO forensics_automation_jobs (name, trigger_type, priority, assigned_analyst)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id`,
		req.Name, req.TriggerType, req.Priority, req.AssignedAnalyst,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ジョブの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending", "evidence_count": 0, "created_at": time.Now().UTC().Format(time.RFC3339)})
}

func (h *ForensicsAutomationHandler) StartJob(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `
		UPDATE forensics_automation_jobs
		SET status='running', started_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND status IN ('pending','failed')`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "開始できるジョブが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "running", "started_at": time.Now().UTC().Format(time.RFC3339)})
}

func (h *ForensicsAutomationHandler) GetEvidence(c *gin.Context) {
	jobID := c.Param("id")
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "forensics_evidence_items")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"evidence": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, job_id, evidence_type, source_path, hash_sha256, file_size, collected_at FROM forensics_evidence_items WHERE job_id = $1 ORDER BY collected_at DESC`,
		jobID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var items []gin.H
	for rows.Next() {
		var id, jid, evidenceType, sourcePath, hashSHA256 string
		var fileSize int64
		var collectedAt time.Time
		if err := rows.Scan(&id, &jid, &evidenceType, &sourcePath, &hashSHA256, &fileSize, &collectedAt); err != nil {
			continue
		}
		items = append(items, gin.H{
			"id":            id,
			"job_id":        jid,
			"evidence_type": evidenceType,
			"source_path":   sourcePath,
			"hash_sha256":   hashSHA256,
			"file_size":     fileSize,
			"collected_at":  collectedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	if items == nil {
		items = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"evidence": items, "total": len(items)})
}

func (h *ForensicsAutomationHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	jobsExists := tableIsThere(ctx, h.pool, "forensics_automation_jobs")
	evidenceExists := tableIsThere(ctx, h.pool, "forensics_evidence_items")

	var totalJobs, activeJobs, completedToday int
	var totalEvidence int
	if jobsExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM forensics_automation_jobs`).Scan(&totalJobs)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM forensics_automation_jobs WHERE status = 'running'`).Scan(&activeJobs)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM forensics_automation_jobs WHERE status = 'completed' AND DATE(completed_at) = CURRENT_DATE`).Scan(&completedToday)) {
			return
		}
	}
	if evidenceExists {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM forensics_evidence_items`).Scan(&totalEvidence)) {
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_jobs":               totalJobs,
		"active_jobs":              activeJobs,
		"completed_today":          completedToday,
		"total_evidence_items":     totalEvidence,
		"avg_duration_minutes":     0,
		"auto_triggered_this_week": 0,
		"modules_available":        []string{"memory_dump", "disk_image", "network_capture", "registry", "event_logs", "prefetch", "shellbag", "mft", "lnk_files"},
	})
}
