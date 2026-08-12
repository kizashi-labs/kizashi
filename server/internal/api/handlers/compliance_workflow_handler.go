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

// ComplianceWorkflowHandler handles compliance workflow endpoints.
type ComplianceWorkflowHandler struct {
	pool *pgxpool.Pool
}

// NewComplianceWorkflowHandler creates a new ComplianceWorkflowHandler.
func NewComplianceWorkflowHandler(pool *pgxpool.Pool) *ComplianceWorkflowHandler {
	return &ComplianceWorkflowHandler{pool: pool}
}

func (h *ComplianceWorkflowHandler) checkWorkflowsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='compliance_workflows')`).Scan(&exists)
	return err == nil && exists
}

func (h *ComplianceWorkflowHandler) checkRunsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='compliance_workflow_runs')`).Scan(&exists)
	return err == nil && exists
}

// ListWorkflows returns all compliance workflows.
// GET /api/v1/admin/compliance-workflows
func (h *ComplianceWorkflowHandler) ListWorkflows(c *gin.Context) {
	if !h.checkWorkflowsTable(c) {
		c.JSON(http.StatusOK, gin.H{"workflows": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	framework := c.Query("framework")
	workflowType := c.Query("workflow_type")
	status := c.Query("status")

	query := `SELECT id, name, framework, workflow_type, status, stages,
	                 trigger_type, schedule, is_active, run_count, created_at, updated_at
	          FROM compliance_workflows WHERE 1=1`
	args := []interface{}{}
	i := 1

	if framework != "" {
		query += ` AND framework = $` + fmt.Sprintf("%d", i)
		args = append(args, framework)
		i++
	}
	if workflowType != "" {
		query += ` AND workflow_type = $` + fmt.Sprintf("%d", i)
		args = append(args, workflowType)
		i++
	}
	if status != "" {
		query += ` AND status = $` + fmt.Sprintf("%d", i)
		args = append(args, status)
		i++
	}
	query += ` ORDER BY created_at DESC`

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Workflow struct {
		ID           string          `json:"id"`
		Name         string          `json:"name"`
		Framework    string          `json:"framework"`
		WorkflowType string          `json:"workflow_type"`
		Status       string          `json:"status"`
		Stages       json.RawMessage `json:"stages"`
		TriggerType  string          `json:"trigger_type"`
		Schedule     *string         `json:"schedule"`
		IsActive     bool            `json:"is_active"`
		RunCount     int             `json:"run_count"`
		CreatedAt    time.Time       `json:"created_at"`
		UpdatedAt    time.Time       `json:"updated_at"`
	}

	var workflows []Workflow
	for rows.Next() {
		var w Workflow
		if err := rows.Scan(&w.ID, &w.Name, &w.Framework, &w.WorkflowType, &w.Status,
			&w.Stages, &w.TriggerType, &w.Schedule, &w.IsActive, &w.RunCount,
			&w.CreatedAt, &w.UpdatedAt); err != nil {
			continue
		}
		workflows = append(workflows, w)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if workflows == nil {
		workflows = []Workflow{}
	}
	c.JSON(http.StatusOK, gin.H{"workflows": workflows, "total": len(workflows)})
}

// CreateWorkflow creates a new compliance workflow.
// POST /api/v1/admin/compliance-workflows
func (h *ComplianceWorkflowHandler) CreateWorkflow(c *gin.Context) {
	if !h.checkWorkflowsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflows table not available"})
		return
	}
	var body struct {
		Name         string          `json:"name"          binding:"required"`
		Framework    string          `json:"framework"     binding:"required"`
		WorkflowType string          `json:"workflow_type" binding:"required"`
		Status       string          `json:"status"`
		Stages       json.RawMessage `json:"stages"`
		TriggerType  string          `json:"trigger_type"`
		Schedule     *string         `json:"schedule"`
		IsActive     *bool           `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name == "" || body.Framework == "" || body.WorkflowType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, framework, and workflow_type are required"})
		return
	}
	if body.Status == "" {
		body.Status = "active"
	}
	if body.TriggerType == "" {
		body.TriggerType = "manual"
	}
	if body.Stages == nil {
		body.Stages = json.RawMessage("[]")
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO compliance_workflows (name, framework, workflow_type, status, stages, trigger_type, schedule, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		body.Name, body.Framework, body.WorkflowType, body.Status,
		body.Stages, body.TriggerType, body.Schedule, isActive,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "workflow created"})
}

// UpdateWorkflow updates a compliance workflow.
// PUT /api/v1/admin/compliance-workflows/:id
func (h *ComplianceWorkflowHandler) UpdateWorkflow(c *gin.Context) {
	if !h.checkWorkflowsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflows table not available"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name         *string         `json:"name"`
		Framework    *string         `json:"framework"`
		WorkflowType *string         `json:"workflow_type"`
		Status       *string         `json:"status"`
		Stages       json.RawMessage `json:"stages"`
		TriggerType  *string         `json:"trigger_type"`
		Schedule     *string         `json:"schedule"`
		IsActive     *bool           `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE compliance_workflows SET
		   name         = COALESCE($2, name),
		   framework    = COALESCE($3, framework),
		   workflow_type= COALESCE($4, workflow_type),
		   status       = COALESCE($5, status),
		   stages       = COALESCE($6, stages),
		   trigger_type = COALESCE($7, trigger_type),
		   schedule     = $8,
		   is_active    = COALESCE($9, is_active),
		   updated_at   = NOW()
		 WHERE id = $1`,
		id, body.Name, body.Framework, body.WorkflowType, body.Status,
		cwfNullableJSON(body.Stages), body.TriggerType, body.Schedule, body.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workflow updated"})
}

// DeleteWorkflow deletes a compliance workflow.
// DELETE /api/v1/admin/compliance-workflows/:id
func (h *ComplianceWorkflowHandler) DeleteWorkflow(c *gin.Context) {
	if !h.checkWorkflowsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflows table not available"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM compliance_workflows WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workflow deleted"})
}

// StartRun starts a new run for a compliance workflow.
// POST /api/v1/admin/compliance-workflows/:id/run
func (h *ComplianceWorkflowHandler) StartRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflow_runs table not available"})
		return
	}
	workflowID := c.Param("id")
	ctx := c.Request.Context()

	// Fetch workflow stages to compute due_date
	var stagesRaw json.RawMessage
	err := h.pool.QueryRow(ctx, `SELECT stages FROM compliance_workflows WHERE id = $1`, workflowID).Scan(&stagesRaw)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}

	// Sum due_days across all stages
	var stages []struct {
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Assignee string   `json:"assignee"`
		DueDays  int      `json:"due_days"`
		Actions  []string `json:"actions"`
	}
	totalDueDays := 0
	if err := json.Unmarshal(stagesRaw, &stages); err == nil {
		for _, s := range stages {
			totalDueDays += s.DueDays
		}
	}

	var dueDate *time.Time
	if totalDueDays > 0 {
		d := time.Now().UTC().AddDate(0, 0, totalDueDays)
		dueDate = &d
	}

	var body struct {
		Assignees json.RawMessage `json:"assignees"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Assignees == nil {
		body.Assignees = json.RawMessage("{}")
	}

	var runID string
	err = h.pool.QueryRow(ctx,
		`INSERT INTO compliance_workflow_runs (workflow_id, assignees, due_date)
		 VALUES ($1, $2, $3) RETURNING id`,
		workflowID, body.Assignees, dueDate,
	).Scan(&runID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Increment run_count on the workflow
	_, _ = h.pool.Exec(ctx, `UPDATE compliance_workflows SET run_count = run_count + 1, updated_at = NOW() WHERE id = $1`, workflowID)

	c.JSON(http.StatusCreated, gin.H{"id": runID, "message": "run started", "due_date": dueDate})
}

// ListRuns lists workflow runs with optional filters.
// GET /api/v1/admin/compliance-workflows/runs
func (h *ComplianceWorkflowHandler) ListRuns(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusOK, gin.H{"runs": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	workflowID := c.Query("workflow_id")
	status := c.Query("status")

	query := `SELECT id, workflow_id, current_stage, status, assignees, stage_results,
	                 due_date, completed_at, created_at, updated_at
	          FROM compliance_workflow_runs WHERE 1=1`
	args := []interface{}{}
	i := 1

	if workflowID != "" {
		query += ` AND workflow_id = $` + fmt.Sprintf("%d", i)
		args = append(args, workflowID)
		i++
	}
	if status != "" {
		query += ` AND status = $` + fmt.Sprintf("%d", i)
		args = append(args, status)
		i++
	}
	query += ` ORDER BY created_at DESC`

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Run struct {
		ID           string          `json:"id"`
		WorkflowID   string          `json:"workflow_id"`
		CurrentStage int             `json:"current_stage"`
		Status       string          `json:"status"`
		Assignees    json.RawMessage `json:"assignees"`
		StageResults json.RawMessage `json:"stage_results"`
		DueDate      *time.Time      `json:"due_date"`
		CompletedAt  *time.Time      `json:"completed_at"`
		CreatedAt    time.Time       `json:"created_at"`
		UpdatedAt    time.Time       `json:"updated_at"`
	}

	var runs []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.WorkflowID, &r.CurrentStage, &r.Status,
			&r.Assignees, &r.StageResults, &r.DueDate, &r.CompletedAt,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if runs == nil {
		runs = []Run{}
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs, "total": len(runs)})
}

// GetRun returns a single workflow run.
// GET /api/v1/admin/compliance-workflows/runs/:id
func (h *ComplianceWorkflowHandler) GetRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflow_runs table not available"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	type Run struct {
		ID           string          `json:"id"`
		WorkflowID   string          `json:"workflow_id"`
		CurrentStage int             `json:"current_stage"`
		Status       string          `json:"status"`
		Assignees    json.RawMessage `json:"assignees"`
		StageResults json.RawMessage `json:"stage_results"`
		DueDate      *time.Time      `json:"due_date"`
		CompletedAt  *time.Time      `json:"completed_at"`
		CreatedAt    time.Time       `json:"created_at"`
		UpdatedAt    time.Time       `json:"updated_at"`
	}

	var r Run
	err := h.pool.QueryRow(ctx,
		`SELECT id, workflow_id, current_stage, status, assignees, stage_results,
		        due_date, completed_at, created_at, updated_at
		 FROM compliance_workflow_runs WHERE id = $1`, id).
		Scan(&r.ID, &r.WorkflowID, &r.CurrentStage, &r.Status,
			&r.Assignees, &r.StageResults, &r.DueDate, &r.CompletedAt,
			&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// AdvanceStage increments the current stage of a run.
// POST /api/v1/admin/compliance-workflows/runs/:id/advance
func (h *ComplianceWorkflowHandler) AdvanceStage(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflow_runs table not available"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	var body struct {
		Result json.RawMessage `json:"result"`
		Notes  string          `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Result == nil {
		body.Result = json.RawMessage("{}")
	}

	// Fetch current run state
	var currentStage int
	var status string
	var stageResultsRaw json.RawMessage
	var workflowID string
	err := h.pool.QueryRow(ctx,
		`SELECT current_stage, status, stage_results, workflow_id FROM compliance_workflow_runs WHERE id = $1`, id).
		Scan(&currentStage, &status, &stageResultsRaw, &workflowID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	if status != "in_progress" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run is not in progress"})
		return
	}

	// Fetch workflow stage count
	var stagesRaw json.RawMessage
	err = h.pool.QueryRow(ctx, `SELECT stages FROM compliance_workflows WHERE id = $1`, workflowID).Scan(&stagesRaw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch workflow stages"})
		return
	}
	var stages []json.RawMessage
	stageCount := 0
	if err := json.Unmarshal(stagesRaw, &stages); err == nil {
		stageCount = len(stages)
	}

	// Append stage result
	var stageResults []json.RawMessage
	_ = json.Unmarshal(stageResultsRaw, &stageResults)
	entry := map[string]interface{}{
		"stage":       currentStage,
		"result":      body.Result,
		"notes":       body.Notes,
		"advanced_at": time.Now().UTC(),
	}
	entryBytes, _ := json.Marshal(entry)
	stageResults = append(stageResults, entryBytes)
	newResultsBytes, _ := json.Marshal(stageResults)

	newStage := currentStage + 1
	newStatus := "in_progress"
	var completedAt *time.Time
	if stageCount > 0 && newStage >= stageCount {
		newStatus = "completed"
		t := time.Now().UTC()
		completedAt = &t
	}

	_, err = h.pool.Exec(ctx,
		`UPDATE compliance_workflow_runs SET
		   current_stage = $2,
		   status        = $3,
		   stage_results = $4,
		   completed_at  = $5,
		   updated_at    = NOW()
		 WHERE id = $1`,
		id, newStage, newStatus, json.RawMessage(newResultsBytes), completedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":       "stage advanced",
		"current_stage": newStage,
		"status":        newStatus,
	})
}

// CancelRun cancels a workflow run.
// POST /api/v1/admin/compliance-workflows/runs/:id/cancel
func (h *ComplianceWorkflowHandler) CancelRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "compliance_workflow_runs table not available"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE compliance_workflow_runs SET status = 'cancelled', updated_at = NOW()
		 WHERE id = $1 AND status = 'in_progress'`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found or not in progress"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "run cancelled"})
}

// cwfNullableJSON returns nil if raw is nil or "null", otherwise returns raw.
func cwfNullableJSON(raw json.RawMessage) interface{} {
	if raw == nil || string(raw) == "null" {
		return nil
	}
	return raw
}
