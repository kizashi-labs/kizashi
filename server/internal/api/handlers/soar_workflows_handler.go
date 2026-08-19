package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// SOARWorkflowHandler manages SOAR-lite incident response automation workflows.
type SOARWorkflowHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewSOARWorkflowHandler creates a new SOARWorkflowHandler.
func NewSOARWorkflowHandler(pool *pgxpool.Pool, nc *nats.Conn) *SOARWorkflowHandler {
	return &SOARWorkflowHandler{pool: pool, nc: nc}
}

// ListWorkflows GET /soar/workflows
func (h *SOARWorkflowHandler) ListWorkflows(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, description, trigger_type, trigger_conditions, actions,
		        enabled, execution_count, last_executed_at, created_by, created_at, updated_at
		 FROM soar_workflows ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workflows"})
		return
	}
	defer rows.Close()

	type Workflow struct {
		ID                string          `json:"id"`
		Name              string          `json:"name"`
		Description       string          `json:"description"`
		TriggerType       string          `json:"trigger_type"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		Actions           json.RawMessage `json:"actions"`
		Enabled           bool            `json:"enabled"`
		ExecutionCount    int             `json:"execution_count"`
		LastExecutedAt    *time.Time      `json:"last_executed_at"`
		CreatedBy         *string         `json:"created_by"`
		CreatedAt         time.Time       `json:"created_at"`
		UpdatedAt         time.Time       `json:"updated_at"`
	}

	workflows := []Workflow{}
	for rows.Next() {
		var w Workflow
		if err := rows.Scan(&w.ID, &w.Name, &w.Description, &w.TriggerType,
			&w.TriggerConditions, &w.Actions, &w.Enabled, &w.ExecutionCount,
			&w.LastExecutedAt, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt); err == nil {
			workflows = append(workflows, w)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workflows"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": workflows})
}

// GetWorkflow GET /soar/workflows/:id
func (h *SOARWorkflowHandler) GetWorkflow(c *gin.Context) {
	id := c.Param("id")

	type Workflow struct {
		ID                string          `json:"id"`
		Name              string          `json:"name"`
		Description       string          `json:"description"`
		TriggerType       string          `json:"trigger_type"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		Actions           json.RawMessage `json:"actions"`
		Enabled           bool            `json:"enabled"`
		ExecutionCount    int             `json:"execution_count"`
		LastExecutedAt    *time.Time      `json:"last_executed_at"`
		CreatedBy         *string         `json:"created_by"`
		CreatedAt         time.Time       `json:"created_at"`
		UpdatedAt         time.Time       `json:"updated_at"`
	}

	var w Workflow
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, trigger_type, trigger_conditions, actions,
		        enabled, execution_count, last_executed_at, created_by, created_at, updated_at
		 FROM soar_workflows WHERE id = $1`, id).
		Scan(&w.ID, &w.Name, &w.Description, &w.TriggerType, &w.TriggerConditions,
			&w.Actions, &w.Enabled, &w.ExecutionCount, &w.LastExecutedAt,
			&w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}

	// Fetch recent executions
	type Execution struct {
		ID               string          `json:"id"`
		TriggerEventID   *string         `json:"trigger_event_id"`
		TriggerType      string          `json:"trigger_type"`
		Status           string          `json:"status"`
		ActionsCompleted json.RawMessage `json:"actions_completed"`
		ErrorMessage     string          `json:"error_message"`
		StartedAt        time.Time       `json:"started_at"`
		CompletedAt      *time.Time      `json:"completed_at"`
	}
	eRows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, trigger_event_id, trigger_type, status, actions_completed,
		        error_message, started_at, completed_at
		 FROM soar_executions WHERE workflow_id = $1 ORDER BY started_at DESC LIMIT 10`, id)
	executions := []Execution{}
	if err == nil {
		defer eRows.Close()
		for eRows.Next() {
			var e Execution
			if err := eRows.Scan(&e.ID, &e.TriggerEventID, &e.TriggerType, &e.Status,
				&e.ActionsCompleted, &e.ErrorMessage, &e.StartedAt, &e.CompletedAt); err == nil {
				executions = append(executions, e)
			}
		}
		if err := eRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": w, "executions": executions})
}

// CreateWorkflow POST /soar/workflows
func (h *SOARWorkflowHandler) CreateWorkflow(c *gin.Context) {
	var req struct {
		Name              string                   `json:"name" binding:"required"`
		Description       string                   `json:"description"`
		TriggerType       string                   `json:"trigger_type"`
		TriggerConditions map[string]interface{}   `json:"trigger_conditions"`
		Actions           []map[string]interface{} `json:"actions"`
		Enabled           *bool                    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.TriggerType == "" {
		req.TriggerType = "alert"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	triggerJSON, _ := json.Marshal(req.TriggerConditions)
	actionsJSON, _ := json.Marshal(req.Actions)
	if string(triggerJSON) == "null" {
		triggerJSON = []byte("{}")
	}
	if string(actionsJSON) == "null" {
		actionsJSON = []byte("[]")
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO soar_workflows (name, description, trigger_type, trigger_conditions, actions, enabled, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		req.Name, req.Description, req.TriggerType, string(triggerJSON),
		string(actionsJSON), enabled, userIDStr).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create workflow"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "workflow created", "id": id})
}

// UpdateWorkflow PUT /soar/workflows/:id
func (h *SOARWorkflowHandler) UpdateWorkflow(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name              *string                  `json:"name"`
		Description       *string                  `json:"description"`
		TriggerType       *string                  `json:"trigger_type"`
		TriggerConditions map[string]interface{}   `json:"trigger_conditions"`
		Actions           []map[string]interface{} `json:"actions"`
		Enabled           *bool                    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var triggerJSON, actionsJSON *string
	if req.TriggerConditions != nil {
		b, _ := json.Marshal(req.TriggerConditions)
		s := string(b)
		triggerJSON = &s
	}
	if req.Actions != nil {
		b, _ := json.Marshal(req.Actions)
		s := string(b)
		actionsJSON = &s
	}

	ct, err := h.pool.Exec(c.Request.Context(),
		`UPDATE soar_workflows
		 SET name = COALESCE($2, name),
		     description = COALESCE($3, description),
		     trigger_type = COALESCE($4, trigger_type),
		     trigger_conditions = COALESCE($5::jsonb, trigger_conditions),
		     actions = COALESCE($6::jsonb, actions),
		     enabled = COALESCE($7, enabled),
		     updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Description, req.TriggerType, triggerJSON, actionsJSON, req.Enabled)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workflow updated"})
}

// DeleteWorkflow DELETE /soar/workflows/:id
func (h *SOARWorkflowHandler) DeleteWorkflow(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM soar_workflows WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workflow deleted"})
}

// ToggleWorkflow POST /soar/workflows/:id/toggle
func (h *SOARWorkflowHandler) ToggleWorkflow(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(),
		`UPDATE soar_workflows SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workflow toggled"})
}

// TriggerWorkflow POST /soar/workflows/:id/trigger
func (h *SOARWorkflowHandler) TriggerWorkflow(c *gin.Context) {
	workflowID := c.Param("id")

	var req struct {
		EventID string                 `json:"event_id"`
		Context map[string]interface{} `json:"context"`
	}
	_ = c.ShouldBindJSON(&req)

	// Fetch workflow to get actions
	var actionsJSON json.RawMessage
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT actions, enabled FROM soar_workflows WHERE id = $1`, workflowID).
		Scan(&actionsJSON, &enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workflow not found"})
		return
	}
	if !enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workflow is disabled"})
		return
	}

	// Parse actions to simulate completion
	var actions []map[string]interface{}
	_ = json.Unmarshal(actionsJSON, &actions)

	completedActions := make([]map[string]interface{}, 0, len(actions))
	for _, action := range actions {
		actionType, _ := action["type"].(string)
		completedActions = append(completedActions, map[string]interface{}{
			"type":   actionType,
			"status": "completed",
		})
	}

	completedJSON, _ := json.Marshal(completedActions)
	now := time.Now()

	var eventID *string
	if req.EventID != "" {
		eventID = &req.EventID
	}

	var execID string
	err = h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO soar_executions (workflow_id, trigger_event_id, trigger_type, status, actions_completed, completed_at)
		 VALUES ($1, $2, 'manual', 'completed', $3, $4) RETURNING id`,
		workflowID, eventID, string(completedJSON), now).Scan(&execID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create execution"})
		return
	}

	// Update workflow execution count and last_executed_at
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE soar_workflows
			 SET execution_count = execution_count + 1, last_executed_at = NOW(), updated_at = NOW()
			 WHERE id = $1`, workflowID); !WriteOK(c, err) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":           "workflow triggered",
		"execution_id":      execID,
		"actions_completed": completedActions,
		"status":            "completed",
	})
}

// GetExecution GET /soar/executions/:id
func (h *SOARWorkflowHandler) GetExecution(c *gin.Context) {
	id := c.Param("id")

	type Execution struct {
		ID               string          `json:"id"`
		WorkflowID       string          `json:"workflow_id"`
		TriggerEventID   *string         `json:"trigger_event_id"`
		TriggerType      string          `json:"trigger_type"`
		Status           string          `json:"status"`
		ActionsCompleted json.RawMessage `json:"actions_completed"`
		ErrorMessage     string          `json:"error_message"`
		StartedAt        time.Time       `json:"started_at"`
		CompletedAt      *time.Time      `json:"completed_at"`
	}

	var e Execution
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, workflow_id, trigger_event_id, trigger_type, status, actions_completed,
		        error_message, started_at, completed_at
		 FROM soar_executions WHERE id = $1`, id).
		Scan(&e.ID, &e.WorkflowID, &e.TriggerEventID, &e.TriggerType, &e.Status,
			&e.ActionsCompleted, &e.ErrorMessage, &e.StartedAt, &e.CompletedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": e})
}

// ListExecutions GET /soar/executions
func (h *SOARWorkflowHandler) ListExecutions(c *gin.Context) {
	workflowID := c.Query("workflow_id")
	status := c.Query("status")

	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1

	if workflowID != "" {
		where += " AND workflow_id = $" + itoa(idx)
		args = append(args, workflowID)
		idx++
	}
	if status != "" {
		where += " AND status = $" + itoa(idx)
		args = append(args, status)
		idx++
	}
	_ = idx

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, workflow_id, trigger_event_id, trigger_type, status, actions_completed,
		        error_message, started_at, completed_at
		 FROM soar_executions `+where+` ORDER BY started_at DESC LIMIT 100`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list executions"})
		return
	}
	defer rows.Close()

	type Execution struct {
		ID               string          `json:"id"`
		WorkflowID       string          `json:"workflow_id"`
		TriggerEventID   *string         `json:"trigger_event_id"`
		TriggerType      string          `json:"trigger_type"`
		Status           string          `json:"status"`
		ActionsCompleted json.RawMessage `json:"actions_completed"`
		ErrorMessage     string          `json:"error_message"`
		StartedAt        time.Time       `json:"started_at"`
		CompletedAt      *time.Time      `json:"completed_at"`
	}

	executions := []Execution{}
	for rows.Next() {
		var e Execution
		if err := rows.Scan(&e.ID, &e.WorkflowID, &e.TriggerEventID, &e.TriggerType,
			&e.Status, &e.ActionsCompleted, &e.ErrorMessage, &e.StartedAt, &e.CompletedAt); err == nil {
			executions = append(executions, e)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list executions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": executions})
}

// GetStats GET /soar/stats
func (h *SOARWorkflowHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	var execToday, execWeek int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM soar_executions WHERE started_at >= NOW() - INTERVAL '24 hours'`).
		Scan(&execToday)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM soar_executions WHERE started_at >= NOW() - INTERVAL '7 days'`).
		Scan(&execWeek)) {
		return
	}

	var totalExec, successExec int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM soar_executions`).Scan(&totalExec)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM soar_executions WHERE status = 'completed'`).Scan(&successExec)) {
		return
	}

	successRate := 0.0
	if totalExec > 0 {
		successRate = float64(successExec) / float64(totalExec) * 100
	}

	type WorkflowStat struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var mostTriggered WorkflowStat
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT w.id, w.name, w.execution_count
			 FROM soar_workflows w ORDER BY w.execution_count DESC LIMIT 1`).
		Scan(&mostTriggered.ID, &mostTriggered.Name, &mostTriggered.Count)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"executions_today":     execToday,
		"executions_this_week": execWeek,
		"success_rate":         successRate,
		"most_triggered":       mostTriggered,
	})
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
