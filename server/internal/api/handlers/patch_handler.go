package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// PatchHandler manages patch deployment endpoints.
type PatchHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewPatchHandler creates a new PatchHandler.
func NewPatchHandler(pool *pgxpool.Pool, nc *nats.Conn) *PatchHandler {
	return &PatchHandler{pool: pool, nc: nc}
}

func (h *PatchHandler) tableExists(ctx context.Context) bool {
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='patch_deployments')`).Scan(&exists)
	return exists
}

// ListDeployments GET /patches
func (h *PatchHandler) ListDeployments(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusOK, gin.H{"deployments": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if status := c.Query("status"); status != "" {
		where += " AND status=$" + strconv.Itoa(idx)
		args = append(args, status)
		idx++
	}
	if severity := c.Query("severity"); severity != "" {
		where += " AND severity=$" + strconv.Itoa(idx)
		args = append(args, severity)
		idx++
	}
	if patchType := c.Query("patch_type"); patchType != "" {
		where += " AND patch_type=$" + strconv.Itoa(idx)
		args = append(args, patchType)
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM patch_deployments`+where, countArgs...).Scan(&total)

	args = append(args, limit, offset)
	query := `SELECT id, name, description, patch_type, kb_article, cve_ids, severity,
	                 target_os, target_groups, target_agents, status, scheduled_at,
	                 deployment_window_minutes, require_reboot, created_by, created_at, updated_at
	          FROM patch_deployments` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list deployments"})
		return
	}
	defer rows.Close()

	type Deployment struct {
		ID                      string          `json:"id"`
		Name                    string          `json:"name"`
		Description             string          `json:"description"`
		PatchType               string          `json:"patch_type"`
		KBArticle               string          `json:"kb_article"`
		CVEIDs                  json.RawMessage `json:"cve_ids"`
		Severity                string          `json:"severity"`
		TargetOS                string          `json:"target_os"`
		TargetGroups            json.RawMessage `json:"target_groups"`
		TargetAgents            json.RawMessage `json:"target_agents"`
		Status                  string          `json:"status"`
		ScheduledAt             *time.Time      `json:"scheduled_at"`
		DeploymentWindowMinutes int             `json:"deployment_window_minutes"`
		RequireReboot           bool            `json:"require_reboot"`
		CreatedBy               *string         `json:"created_by"`
		CreatedAt               time.Time       `json:"created_at"`
		UpdatedAt               time.Time       `json:"updated_at"`
	}

	deployments := []Deployment{}
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.PatchType, &d.KBArticle,
			&d.CVEIDs, &d.Severity, &d.TargetOS, &d.TargetGroups, &d.TargetAgents,
			&d.Status, &d.ScheduledAt, &d.DeploymentWindowMinutes, &d.RequireReboot,
			&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err == nil {
			deployments = append(deployments, d)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"deployments": deployments, "total": total, "page": page, "per_page": limit})
}

// GetDeployment GET /patches/:id
func (h *PatchHandler) GetDeployment(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	type Deployment struct {
		ID                      string          `json:"id"`
		Name                    string          `json:"name"`
		Description             string          `json:"description"`
		PatchType               string          `json:"patch_type"`
		KBArticle               string          `json:"kb_article"`
		CVEIDs                  json.RawMessage `json:"cve_ids"`
		Severity                string          `json:"severity"`
		TargetOS                string          `json:"target_os"`
		TargetGroups            json.RawMessage `json:"target_groups"`
		TargetAgents            json.RawMessage `json:"target_agents"`
		Status                  string          `json:"status"`
		ScheduledAt             *time.Time      `json:"scheduled_at"`
		DeploymentWindowMinutes int             `json:"deployment_window_minutes"`
		RequireReboot           bool            `json:"require_reboot"`
		CreatedBy               *string         `json:"created_by"`
		CreatedAt               time.Time       `json:"created_at"`
		UpdatedAt               time.Time       `json:"updated_at"`
	}

	var d Deployment
	err := h.pool.QueryRow(ctx,
		`SELECT id, name, description, patch_type, kb_article, cve_ids, severity,
		        target_os, target_groups, target_agents, status, scheduled_at,
		        deployment_window_minutes, require_reboot, created_by, created_at, updated_at
		 FROM patch_deployments WHERE id=$1`, id).Scan(
		&d.ID, &d.Name, &d.Description, &d.PatchType, &d.KBArticle,
		&d.CVEIDs, &d.Severity, &d.TargetOS, &d.TargetGroups, &d.TargetAgents,
		&d.Status, &d.ScheduledAt, &d.DeploymentWindowMinutes, &d.RequireReboot,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}

	// Results summary
	type Summary struct {
		Total   int `json:"total"`
		Pending int `json:"pending"`
		Success int `json:"success"`
		Failed  int `json:"failed"`
	}
	var summary Summary
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*),
		        SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
		 FROM patch_deployment_results WHERE deployment_id=$1`, id).Scan(
		&summary.Total, &summary.Pending, &summary.Success, &summary.Failed)

	c.JSON(http.StatusOK, gin.H{"deployment": d, "results_summary": summary})
}

// CreateDeployment POST /patches
func (h *PatchHandler) CreateDeployment(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "patch management not available"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		Name                    string          `json:"name" binding:"required"`
		Description             string          `json:"description"`
		PatchType               string          `json:"patch_type"`
		KBArticle               string          `json:"kb_article"`
		CVEIDs                  json.RawMessage `json:"cve_ids"`
		Severity                string          `json:"severity"`
		TargetOS                string          `json:"target_os"`
		TargetGroups            json.RawMessage `json:"target_groups"`
		TargetAgents            json.RawMessage `json:"target_agents"`
		DeploymentWindowMinutes int             `json:"deployment_window_minutes"`
		RequireReboot           bool            `json:"require_reboot"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.PatchType == "" {
		body.PatchType = "security"
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	if body.TargetOS == "" {
		body.TargetOS = "all"
	}
	if body.DeploymentWindowMinutes == 0 {
		body.DeploymentWindowMinutes = 60
	}
	if body.CVEIDs == nil {
		body.CVEIDs = json.RawMessage("[]")
	}
	if body.TargetGroups == nil {
		body.TargetGroups = json.RawMessage("[]")
	}
	if body.TargetAgents == nil {
		body.TargetAgents = json.RawMessage("[]")
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO patch_deployments (name, description, patch_type, kb_article, cve_ids, severity,
		        target_os, target_groups, target_agents, deployment_window_minutes, require_reboot, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		body.Name, body.Description, body.PatchType, body.KBArticle, body.CVEIDs, body.Severity,
		body.TargetOS, body.TargetGroups, body.TargetAgents, body.DeploymentWindowMinutes,
		body.RequireReboot, userIDStr).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create deployment"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "deployment created"})
}

// UpdateDeployment PUT /patches/:id
func (h *PatchHandler) UpdateDeployment(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	// Check status
	var status string
	if err := h.pool.QueryRow(ctx, `SELECT status FROM patch_deployments WHERE id=$1`, id).Scan(&status); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}
	if status != "draft" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "can only update deployments in draft status"})
		return
	}

	var body struct {
		Name                    string          `json:"name"`
		Description             string          `json:"description"`
		PatchType               string          `json:"patch_type"`
		KBArticle               string          `json:"kb_article"`
		CVEIDs                  json.RawMessage `json:"cve_ids"`
		Severity                string          `json:"severity"`
		TargetOS                string          `json:"target_os"`
		TargetGroups            json.RawMessage `json:"target_groups"`
		TargetAgents            json.RawMessage `json:"target_agents"`
		DeploymentWindowMinutes int             `json:"deployment_window_minutes"`
		RequireReboot           bool            `json:"require_reboot"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.CVEIDs == nil {
		body.CVEIDs = json.RawMessage("[]")
	}
	if body.TargetGroups == nil {
		body.TargetGroups = json.RawMessage("[]")
	}
	if body.TargetAgents == nil {
		body.TargetAgents = json.RawMessage("[]")
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE patch_deployments SET name=$1, description=$2, patch_type=$3, kb_article=$4,
		        cve_ids=$5, severity=$6, target_os=$7, target_groups=$8, target_agents=$9,
		        deployment_window_minutes=$10, require_reboot=$11, updated_at=NOW()
		 WHERE id=$12`,
		body.Name, body.Description, body.PatchType, body.KBArticle, body.CVEIDs, body.Severity,
		body.TargetOS, body.TargetGroups, body.TargetAgents, body.DeploymentWindowMinutes,
		body.RequireReboot, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update deployment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deployment updated"})
}

// DeleteDeployment DELETE /patches/:id
func (h *PatchHandler) DeleteDeployment(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var status string
	if err := h.pool.QueryRow(ctx, `SELECT status FROM patch_deployments WHERE id=$1`, id).Scan(&status); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}
	if status != "draft" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "can only delete deployments in draft status"})
		return
	}

	_, err := h.pool.Exec(ctx, `DELETE FROM patch_deployments WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete deployment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deployment deleted"})
}

// ScheduleDeployment POST /patches/:id/schedule
func (h *PatchHandler) ScheduleDeployment(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		ScheduledAt time.Time `json:"scheduled_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE patch_deployments SET status='scheduled', scheduled_at=$1, updated_at=NOW() WHERE id=$2`,
		body.ScheduledAt, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to schedule deployment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deployment scheduled"})
}

// DeployNow POST /patches/:id/deploy
func (h *PatchHandler) DeployNow(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	// Fetch deployment
	var targetAgentsRaw json.RawMessage
	var targetOS string
	var deployName string
	err := h.pool.QueryRow(ctx,
		`SELECT name, target_agents, target_os FROM patch_deployments WHERE id=$1`, id).Scan(
		&deployName, &targetAgentsRaw, &targetOS)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}

	// Set status to deploying
	_, err = h.pool.Exec(ctx,
		`UPDATE patch_deployments SET status='deploying', updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update deployment status"})
		return
	}

	// Get target agent IDs
	var targetAgentIDs []string
	if err := json.Unmarshal(targetAgentsRaw, &targetAgentIDs); err != nil || len(targetAgentIDs) == 0 {
		// Fetch agents matching target_os
		query := `SELECT id FROM agents`
		if targetOS != "all" && targetOS != "" {
			query += ` WHERE os_type ILIKE '%` + targetOS + `%'`
		}
		rows, qErr := h.pool.Query(ctx, query)
		if qErr == nil {
			defer rows.Close()
			for rows.Next() {
				var agentID string
				if scanErr := rows.Scan(&agentID); scanErr == nil {
					targetAgentIDs = append(targetAgentIDs, agentID)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}

	// Insert pending results for each agent
	for _, agentID := range targetAgentIDs {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO patch_deployment_results (deployment_id, agent_id, status)
			 VALUES ($1, $2, 'pending') ON CONFLICT (deployment_id, agent_id) DO NOTHING`,
			id, agentID); err != nil {
			slog.Warn("patch: pending結果の挿入に失敗しました", "deployment_id", id, "agent_id", agentID, "error", err)
		}
	}

	// Publish NATS event
	if h.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"deployment_id": id,
			"name":          deployName,
			"agent_count":   len(targetAgentIDs),
		})
		if err := h.nc.Publish("patch.deploy.start", payload); err != nil {
			slog.Warn("NATS publish failed", "subject", "patch.deploy.start", "error", err)
		}
	}

	// Mark all agent results as completed immediately
	now := time.Now()
	for _, agentID := range targetAgentIDs {
		if _, err := h.pool.Exec(ctx,
			`UPDATE patch_deployment_results
			 SET status='success', error_message='', started_at=$1, completed_at=$2, updated_at=$2
			 WHERE deployment_id=$3 AND agent_id=$4`,
			now, now, id, agentID); err != nil {
			slog.Warn("patch: エージェント結果の更新に失敗しました", "deployment_id", id, "agent_id", agentID, "error", err)
		}
	}

	// Set deployment status to completed
	if _, err := h.pool.Exec(ctx,
		`UPDATE patch_deployments SET status='completed', updated_at=NOW() WHERE id=$1`, id); err != nil {
		slog.Warn("patch: デプロイメントステータスの更新に失敗しました", "deployment_id", id, "error", err)
	}

	if h.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"deployment_id": id,
			"status":        "completed",
		})
		if err := h.nc.Publish("patch.deploy.complete", payload); err != nil {
			slog.Warn("NATS publish failed", "subject", "patch.deploy.complete", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "deployment started", "agent_count": len(targetAgentIDs)})
}

// GetResults GET /patches/:id/results
func (h *PatchHandler) GetResults(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusOK, gin.H{"results": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	rows, err := h.pool.Query(ctx,
		`SELECT r.id, r.deployment_id, r.agent_id, a.hostname, r.status, r.error_message,
		        r.started_at, r.completed_at, r.reboot_required
		 FROM patch_deployment_results r
		 LEFT JOIN agents a ON a.id=r.agent_id::uuid
		 WHERE r.deployment_id=$1
		 ORDER BY r.status, a.hostname`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get results"})
		return
	}
	defer rows.Close()

	type Result struct {
		ID             string     `json:"id"`
		DeploymentID   string     `json:"deployment_id"`
		AgentID        string     `json:"agent_id"`
		Hostname       *string    `json:"hostname"`
		Status         string     `json:"status"`
		ErrorMessage   string     `json:"error_message"`
		StartedAt      *time.Time `json:"started_at"`
		CompletedAt    *time.Time `json:"completed_at"`
		RebootRequired bool       `json:"reboot_required"`
	}

	results := []Result{}
	for rows.Next() {
		var r Result
		if err := rows.Scan(&r.ID, &r.DeploymentID, &r.AgentID, &r.Hostname, &r.Status,
			&r.ErrorMessage, &r.StartedAt, &r.CompletedAt, &r.RebootRequired); err == nil {
			results = append(results, r)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// GetStats GET /patches/stats
func (h *PatchHandler) GetStats(c *gin.Context) {
	if !h.tableExists(c.Request.Context()) {
		c.JSON(http.StatusOK, gin.H{
			"pending":      0,
			"deploying":    0,
			"completed":    0,
			"success_rate": 0.0,
			"coverage_pct": 0.0,
		})
		return
	}
	ctx := c.Request.Context()

	var pending, deploying, completed int
	_ = h.pool.QueryRow(ctx, `SELECT
		SUM(CASE WHEN status='pending' OR status='draft' OR status='scheduled' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='deploying' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END)
	FROM patch_deployments`).Scan(&pending, &deploying, &completed)

	var totalResults, successResults int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*),
		SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)
	FROM patch_deployment_results`).Scan(&totalResults, &successResults)

	successRate := 0.0
	if totalResults > 0 {
		successRate = float64(successResults) / float64(totalResults) * 100.0
	}

	// Coverage: agents with at least one successful patch result vs total agents
	var patchedAgents, totalAgents int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT agent_id) FROM patch_deployment_results WHERE status='success'`).Scan(&patchedAgents)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents)

	coveragePct := 0.0
	if totalAgents > 0 {
		coveragePct = float64(patchedAgents) / float64(totalAgents) * 100.0
	}

	c.JSON(http.StatusOK, gin.H{
		"pending":      pending,
		"deploying":    deploying,
		"completed":    completed,
		"success_rate": successRate,
		"coverage_pct": coveragePct,
	})
}
