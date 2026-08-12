package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PatchAutomationHandler serves patch policies / jobs from the migration-144
// tables. It previously returned hard-coded fictitious data (fake policies,
// jobs and CVEs regenerated with fresh UUIDs on every request) and ignored the
// real tables entirely.
type PatchAutomationHandler struct{ pool *pgxpool.Pool }

func NewPatchAutomationHandler(pool *pgxpool.Pool) *PatchAutomationHandler {
	return &PatchAutomationHandler{pool: pool}
}

// windowLabel renders the maintenance_window jsonb ({day,start,duration_hours})
// as a human-readable string for the UI.
func windowLabel(raw []byte) string {
	var w struct {
		Day           string `json:"day"`
		Start         string `json:"start"`
		DurationHours int    `json:"duration_hours"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &w) != nil || (w.Day == "" && w.Start == "") {
		return ""
	}
	label := w.Day
	if w.Start != "" {
		label = strings.TrimSpace(label + " " + w.Start)
	}
	if w.DurationHours > 0 {
		label = fmt.Sprintf("%s (%dh)", label, w.DurationHours)
	}
	return label
}

// ListPolicies returns patch policies with frontend-shaped fields.
// GET /api/v1/admin/patch-automation  /  GET .../patch-automation/policies
func (h *PatchAutomationHandler) ListPolicies(c *gin.Context) {
	ctx := c.Request.Context()
	policies := []gin.H{}
	rows, err := h.pool.Query(ctx, `
		SELECT id, name, severity_filter, auto_approve_severity, maintenance_window, enabled
		FROM patch_policies ORDER BY name`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, name string
			var severities, autoApprove []string
			var window []byte
			var enabled bool
			if err := rows.Scan(&id, &name, &severities, &autoApprove, &window, &enabled); err != nil {
				continue
			}
			if severities == nil {
				severities = []string{}
			}
			policies = append(policies, gin.H{
				"id":           id,
				"name":         name,
				"severities":   severities,
				"auto_approve": len(autoApprove) > 0,
				"window":       windowLabel(window),
				"enabled":      enabled,
			})
		}
		if err := rows.Err(); err != nil {
			slog.Warn("patch policies row iteration error", "error", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

// CreatePolicy inserts a patch policy.
// POST /api/v1/admin/patch-automation
func (h *PatchAutomationHandler) CreatePolicy(c *gin.Context) {
	var req struct {
		Name                string   `json:"name" binding:"required"`
		SeverityFilter      []string `json:"severity_filter"`
		AutoApproveSeverity []string `json:"auto_approve_severity"`
		Enabled             *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.SeverityFilter == nil {
		req.SeverityFilter = []string{"critical", "high"}
	}
	if req.AutoApproveSeverity == nil {
		req.AutoApproveSeverity = []string{}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO patch_policies (name, severity_filter, auto_approve_severity, enabled)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		req.Name, req.SeverityFilter, req.AutoApproveSeverity, enabled,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// TogglePolicy flips a policy's enabled flag.
// POST /api/v1/admin/patch-automation/policies/:id/toggle
func (h *PatchAutomationHandler) TogglePolicy(c *gin.Context) {
	id := c.Param("id")
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE patch_policies SET enabled = NOT enabled, updated_at = NOW()
		WHERE id = $1 RETURNING enabled`, id).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": enabled})
}

// ListJobs returns patch jobs from the real table.
// GET /api/v1/admin/patch-automation/jobs
func (h *PatchAutomationHandler) ListJobs(c *gin.Context) {
	ctx := c.Request.Context()
	jobs := []gin.H{}
	rows, err := h.pool.Query(ctx, `
		SELECT id, name, status, total_endpoints, patched_count, failed_count, pending_reboot,
		       scheduled_at, started_at, completed_at
		FROM patch_jobs ORDER BY created_at DESC LIMIT 100`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, name, status string
			var total, patched, failed, reboot int
			var scheduledAt, startedAt, completedAt *time.Time
			if err := rows.Scan(&id, &name, &status, &total, &patched, &failed, &reboot,
				&scheduledAt, &startedAt, &completedAt); err != nil {
				continue
			}
			job := gin.H{
				"id": id, "name": name, "status": status,
				"total_endpoints": total, "patched_count": patched,
				"failed_count": failed, "pending_reboot": reboot,
			}
			if scheduledAt != nil {
				job["scheduled_at"] = scheduledAt.UTC().Format(time.RFC3339)
			}
			if startedAt != nil {
				job["started_at"] = startedAt.UTC().Format(time.RFC3339)
			}
			if completedAt != nil {
				job["completed_at"] = completedAt.UTC().Format(time.RFC3339)
			}
			jobs = append(jobs, job)
		}
		if err := rows.Err(); err != nil {
			slog.Warn("patch jobs row iteration error", "error", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": len(jobs)})
}

// CreateJob inserts a patch job.
// POST /api/v1/admin/patch-automation/jobs
func (h *PatchAutomationHandler) CreateJob(c *gin.Context) {
	var req struct {
		Name           string   `json:"name" binding:"required"`
		PolicyID       *string  `json:"policy_id"`
		PatchIDs       []string `json:"patch_ids"`
		TotalEndpoints int      `json:"total_endpoints"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.PatchIDs == nil {
		req.PatchIDs = []string{}
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO patch_jobs (name, policy_id, patch_ids, total_endpoints)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		req.Name, req.PolicyID, req.PatchIDs, req.TotalEndpoints,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ジョブの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending"})
}

// ApproveJob moves a pending job to approved (previously returned success
// unconditionally without touching the DB).
// POST /api/v1/admin/patch-automation/jobs/:id/approve
func (h *PatchAutomationHandler) ApproveJob(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `
		UPDATE patch_jobs SET status='approved' WHERE id=$1 AND status='pending'`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "承認できるジョブが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "approved"})
}

// GetMissingPatches returns detected missing patches. There is no patch/
// vulnerability scan data source yet, so this honestly returns an empty list
// instead of the previous hard-coded fictitious CVEs.
func (h *PatchAutomationHandler) GetMissingPatches(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"patches": []gin.H{}, "total": 0})
}

// GetStats aggregates real numbers from patch_jobs (previously hard-coded).
func (h *PatchAutomationHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	var jobsThisMonth, completed, failed int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM patch_jobs WHERE created_at >= date_trunc('month', NOW())`).Scan(&jobsThisMonth)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM patch_jobs WHERE status='completed'`).Scan(&completed)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM patch_jobs WHERE status IN ('failed','rolled_back')`).Scan(&failed)
	successRate := 0.0
	if completed+failed > 0 {
		successRate = float64(completed) / float64(completed+failed) * 100.0
	}
	var totalPatched, totalTargets int
	_ = h.pool.QueryRow(ctx, `SELECT COALESCE(SUM(patched_count),0), COALESCE(SUM(total_endpoints),0) FROM patch_jobs`).Scan(&totalPatched, &totalTargets)
	complianceRate := 0.0
	if totalTargets > 0 {
		complianceRate = float64(totalPatched) / float64(totalTargets) * 100.0
	}
	c.JSON(http.StatusOK, gin.H{
		"patch_compliance_rate": complianceRate,
		"jobs_this_month":       jobsThisMonth,
		"success_rate":          successRate,
		"critical_missing":      0, "high_missing": 0, "medium_missing": 0,
		"avg_patch_lag_days": 0,
	})
}
