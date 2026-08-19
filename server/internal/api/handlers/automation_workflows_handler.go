package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AutomationWorkflowsHandler manages automation workflows.
// GET/POST              /api/v1/admin/automation/workflows
// PUT/DELETE /:id       /api/v1/admin/automation/workflows/:id
// PUT        /:id status /api/v1/admin/automation/workflows/:id (toggle status)
// POST       /:id/run   /api/v1/admin/automation/workflows/:id/run
// GET /history          /api/v1/admin/automation/workflows/history
type AutomationWorkflowsHandler struct {
	pool *pgxpool.Pool
}

func NewAutomationWorkflowsHandler(pool *pgxpool.Pool) *AutomationWorkflowsHandler {
	return &AutomationWorkflowsHandler{pool: pool}
}

func (h *AutomationWorkflowsHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "automation_workflows")
}

type autoWorkflow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Trigger     json.RawMessage `json:"trigger"`
	Actions     json.RawMessage `json:"actions"`
	Status      string          `json:"status"`
	RunCount    int             `json:"run_count"`
	SuccessRate float64         `json:"success_rate"`
	LastRun     *string         `json:"last_run"`
	CreatedAt   string          `json:"created_at"`
}

type autoRunHistory struct {
	ID          string          `json:"id"`
	WorkflowID  string          `json:"workflow_id"`
	TriggerInfo string          `json:"trigger_info"`
	StartedAt   string          `json:"started_at"`
	DurationMs  int             `json:"duration_ms"`
	Status      string          `json:"status"`
	Steps       json.RawMessage `json:"steps"`
}

// List returns all workflows.
// GET /api/v1/admin/automation/workflows
func (h *AutomationWorkflowsHandler) List(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description,
		        COALESCE(trigger,'{}')::jsonb, COALESCE(actions,'[]')::jsonb,
		        status, run_count, success_rate, last_run, created_at
		 FROM automation_workflows ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list workflows"})
		return
	}
	defer rows.Close()

	var workflows []autoWorkflow
	for rows.Next() {
		var w autoWorkflow
		var createdAt time.Time
		var lastRun *time.Time
		if err := rows.Scan(
			&w.ID, &w.Name, &w.Description, &w.Trigger, &w.Actions,
			&w.Status, &w.RunCount, &w.SuccessRate, &lastRun, &createdAt,
		); err != nil {
			continue
		}
		w.CreatedAt = createdAt.Format(time.RFC3339)
		if lastRun != nil {
			s := lastRun.Format(time.RFC3339)
			w.LastRun = &s
		}
		workflows = append(workflows, w)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list workflows"})
		return
	}
	if workflows == nil {
		workflows = []autoWorkflow{}
	}
	c.JSON(http.StatusOK, workflows)
}

// Create creates a new workflow.
// POST /api/v1/admin/automation/workflows
func (h *AutomationWorkflowsHandler) Create(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Automation tables not available"})
		return
	}
	var body struct {
		Name        string          `json:"name" binding:"required"`
		Description string          `json:"description"`
		Trigger     json.RawMessage `json:"trigger"`
		Actions     json.RawMessage `json:"actions"`
		Status      string          `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Status == "" {
		body.Status = "draft"
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO automation_workflows (name, description, trigger, actions, status)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		body.Name, body.Description, body.Trigger, body.Actions, body.Status,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create workflow"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Workflow created"})
}

// Update updates a workflow.
// PUT /api/v1/admin/automation/workflows/:id
func (h *AutomationWorkflowsHandler) Update(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	var body struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Trigger     json.RawMessage `json:"trigger"`
		Actions     json.RawMessage `json:"actions"`
		Status      string          `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE automation_workflows
		 SET name=$1, description=$2, trigger=$3, actions=$4, status=$5
		 WHERE id=$6`,
		body.Name, body.Description, body.Trigger, body.Actions, body.Status, id,
	)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workflow updated"})
}

// Delete deletes a workflow.
// DELETE /api/v1/admin/automation/workflows/:id
func (h *AutomationWorkflowsHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM automation_workflows WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete workflow"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workflow deleted"})
}

// Run executes a workflow on demand.
// POST /api/v1/admin/automation/workflows/:id/run
func (h *AutomationWorkflowsHandler) Run(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	ctx := c.Request.Context()
	if h.tableExists(c) {
		if _, err := h.pool.Exec(ctx,
			`UPDATE automation_workflows SET run_count=run_count+1, last_run=NOW() WHERE id=$1`, id); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workflow triggered", "run_id": generateShortID()})
}

// ListHistory returns recent workflow run history.
// GET /api/v1/admin/automation/workflows/history
func (h *AutomationWorkflowsHandler) ListHistory(c *gin.Context) {
	ctx := c.Request.Context()
	ok := tableIsThere(ctx, h.pool, "automation_run_history")
	if !ok {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	rows, err := h.pool.Query(ctx,
		`SELECT id, workflow_id, trigger_info, started_at, duration_ms, status,
		        COALESCE(steps,'[]')::jsonb
		 FROM automation_run_history ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list history"})
		return
	}
	defer rows.Close()

	var history []autoRunHistory
	for rows.Next() {
		var rh autoRunHistory
		var startedAt time.Time
		if err := rows.Scan(
			&rh.ID, &rh.WorkflowID, &rh.TriggerInfo, &startedAt,
			&rh.DurationMs, &rh.Status, &rh.Steps,
		); err != nil {
			continue
		}
		rh.StartedAt = startedAt.Format(time.RFC3339)
		history = append(history, rh)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list history"})
		return
	}
	if history == nil {
		history = []autoRunHistory{}
	}
	c.JSON(http.StatusOK, history)
}

// generateShortID returns a simple run ID.
func generateShortID() string {
	return time.Now().Format("20060102150405")
}
