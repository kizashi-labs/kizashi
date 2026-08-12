package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentPlaybookHandler manages incident response playbooks.
type IncidentPlaybookHandler struct {
	pool *pgxpool.Pool
}

// NewIncidentPlaybookHandler creates a new IncidentPlaybookHandler.
func NewIncidentPlaybookHandler(pool *pgxpool.Pool) *IncidentPlaybookHandler {
	return &IncidentPlaybookHandler{pool: pool}
}

type incidentPlaybook struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	IncidentType      string      `json:"incident_type"`
	SeverityThreshold int         `json:"severity_threshold"`
	Steps             interface{} `json:"steps"`
	AutoAssign        bool        `json:"auto_assign"`
	Enabled           bool        `json:"enabled"`
	UsageCount        int         `json:"usage_count"`
	CreatedBy         *string     `json:"created_by,omitempty"`
	CreatedAt         string      `json:"created_at"`
	UpdatedAt         string      `json:"updated_at"`
}

func scanIncidentPlaybook(row interface{ Scan(...any) error }) (*incidentPlaybook, error) {
	var pb incidentPlaybook
	var createdAt, updatedAt time.Time
	var stepsRaw []byte
	err := row.Scan(
		&pb.ID, &pb.Name, &pb.Description, &pb.IncidentType,
		&pb.SeverityThreshold, &stepsRaw, &pb.AutoAssign, &pb.Enabled,
		&pb.UsageCount, &pb.CreatedBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	pb.CreatedAt = createdAt.Format(time.RFC3339)
	pb.UpdatedAt = updatedAt.Format(time.RFC3339)
	if stepsRaw != nil {
		_ = json.Unmarshal(stepsRaw, &pb.Steps)
	}
	if pb.Steps == nil {
		pb.Steps = []interface{}{}
	}
	return &pb, nil
}

const ipbCols = `id, name, description, incident_type, severity_threshold, steps,
	auto_assign, enabled, usage_count, created_by, created_at, updated_at`

// List returns all incident playbooks.
// GET /api/v1/playbooks/incident
func (h *IncidentPlaybookHandler) List(c *gin.Context) {
	ctx := c.Request.Context()

	var exists bool
	_ = h.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name = 'incident_playbooks'
	)`).Scan(&exists)
	if !exists {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT `+ipbCols+` FROM incident_playbooks ORDER BY created_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list incident playbooks"})
		return
	}
	defer rows.Close()

	playbooks := []*incidentPlaybook{}
	for rows.Next() {
		pb, err := scanIncidentPlaybook(rows)
		if err == nil {
			playbooks = append(playbooks, pb)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"data": playbooks, "total": len(playbooks)})
}

// Get returns a single incident playbook by ID.
// GET /api/v1/playbooks/incident/:id
func (h *IncidentPlaybookHandler) Get(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+ipbCols+` FROM incident_playbooks WHERE id = $1`, id,
	)
	pb, err := scanIncidentPlaybook(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Incident playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get incident playbook"})
		return
	}
	c.JSON(http.StatusOK, pb)
}

// Create creates a new incident playbook.
// POST /api/v1/playbooks/incident
func (h *IncidentPlaybookHandler) Create(c *gin.Context) {
	var req struct {
		Name              string        `json:"name" binding:"required"`
		Description       string        `json:"description"`
		IncidentType      string        `json:"incident_type"`
		SeverityThreshold int           `json:"severity_threshold"`
		Steps             []interface{} `json:"steps"`
		AutoAssign        bool          `json:"auto_assign"`
		Enabled           *bool         `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.IncidentType == "" {
		req.IncidentType = "general"
	}
	if req.SeverityThreshold == 0 {
		req.SeverityThreshold = 5
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Steps == nil {
		req.Steps = []interface{}{}
	}

	stepsJSON, _ := json.Marshal(req.Steps)

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	var createdBy *string
	if uid != "" {
		createdBy = &uid
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO incident_playbooks
		  (name, description, incident_type, severity_threshold, steps, auto_assign, enabled, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING `+ipbCols,
		req.Name, req.Description, req.IncidentType, req.SeverityThreshold,
		stepsJSON, req.AutoAssign, enabled, createdBy,
	)
	pb, err := scanIncidentPlaybook(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create incident playbook"})
		return
	}
	c.JSON(http.StatusCreated, pb)
}

// Update updates an existing incident playbook.
// PUT /api/v1/playbooks/incident/:id
func (h *IncidentPlaybookHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name              string        `json:"name" binding:"required"`
		Description       string        `json:"description"`
		IncidentType      string        `json:"incident_type"`
		SeverityThreshold int           `json:"severity_threshold"`
		Steps             []interface{} `json:"steps"`
		AutoAssign        bool          `json:"auto_assign"`
		Enabled           *bool         `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Steps == nil {
		req.Steps = []interface{}{}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	stepsJSON, _ := json.Marshal(req.Steps)

	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE incident_playbooks SET
		   name               = $2,
		   description        = $3,
		   incident_type      = $4,
		   severity_threshold = $5,
		   steps              = $6,
		   auto_assign        = $7,
		   enabled            = $8,
		   updated_at         = NOW()
		 WHERE id = $1
		 RETURNING `+ipbCols,
		id, req.Name, req.Description, req.IncidentType,
		req.SeverityThreshold, stepsJSON, req.AutoAssign, enabled,
	)
	pb, err := scanIncidentPlaybook(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Incident playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update incident playbook"})
		return
	}
	c.JSON(http.StatusOK, pb)
}

// Delete removes an incident playbook.
// DELETE /api/v1/playbooks/incident/:id
func (h *IncidentPlaybookHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM incident_playbooks WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete incident playbook"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Incident playbook not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Incident playbook deleted"})
}

// Execute creates a playbook execution record for an incident.
// POST /api/v1/playbooks/incident/:id/execute
func (h *IncidentPlaybookHandler) Execute(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IncidentID string `json:"incident_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.IncidentID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "incident_id is required"})
		return
	}

	ctx := c.Request.Context()

	// Get playbook to include steps in response
	pbRow := h.pool.QueryRow(ctx, `SELECT `+ipbCols+` FROM incident_playbooks WHERE id = $1`, id)
	pb, err := scanIncidentPlaybook(pbRow)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Incident playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get playbook"})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	var startedBy *string
	if uid != "" {
		startedBy = &uid
	}

	var execID string
	err = h.pool.QueryRow(ctx,
		`INSERT INTO playbook_executions (playbook_id, incident_id, started_by)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		id, req.IncidentID, startedBy,
	).Scan(&execID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create execution"})
		return
	}

	// Increment usage count
	_, _ = h.pool.Exec(ctx,
		`UPDATE incident_playbooks SET usage_count = usage_count + 1 WHERE id = $1`, id,
	)

	c.JSON(http.StatusCreated, gin.H{
		"execution_id": execID,
		"playbook_id":  id,
		"incident_id":  req.IncidentID,
		"status":       "in_progress",
		"steps":        pb.Steps,
		"started_by":   startedBy,
	})
}

// GetExecution returns a specific playbook execution.
// GET /api/v1/playbooks/executions/:execId
func (h *IncidentPlaybookHandler) GetExecution(c *gin.Context) {
	execID := c.Param("execId")

	type execution struct {
		ID             string      `json:"id"`
		PlaybookID     string      `json:"playbook_id"`
		IncidentID     string      `json:"incident_id"`
		Status         string      `json:"status"`
		CompletedSteps interface{} `json:"completed_steps"`
		StartedBy      *string     `json:"started_by,omitempty"`
		StartedAt      string      `json:"started_at"`
		CompletedAt    *string     `json:"completed_at,omitempty"`
	}

	var ex execution
	var startedAt time.Time
	var completedAt *time.Time
	var completedStepsRaw []byte

	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, playbook_id, incident_id, status, completed_steps, started_by, started_at, completed_at
		 FROM playbook_executions WHERE id = $1`,
		execID,
	).Scan(
		&ex.ID, &ex.PlaybookID, &ex.IncidentID, &ex.Status,
		&completedStepsRaw, &ex.StartedBy, &startedAt, &completedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Execution not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get execution"})
		return
	}

	ex.StartedAt = startedAt.Format(time.RFC3339)
	if completedAt != nil {
		s := completedAt.Format(time.RFC3339)
		ex.CompletedAt = &s
	}
	if completedStepsRaw != nil {
		_ = json.Unmarshal(completedStepsRaw, &ex.CompletedSteps)
	}
	if ex.CompletedSteps == nil {
		ex.CompletedSteps = []interface{}{}
	}

	c.JSON(http.StatusOK, ex)
}

// CompleteStep marks a step in an execution as completed.
// POST /api/v1/playbooks/executions/:execId/steps/:stepId/complete
func (h *IncidentPlaybookHandler) CompleteStep(c *gin.Context) {
	execID := c.Param("execId")
	stepID := c.Param("stepId")
	ctx := c.Request.Context()

	// Get current execution
	var completedStepsRaw []byte
	var playbookID, status string
	err := h.pool.QueryRow(ctx,
		`SELECT playbook_id, status, completed_steps FROM playbook_executions WHERE id = $1`,
		execID,
	).Scan(&playbookID, &status, &completedStepsRaw)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Execution not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get execution"})
		return
	}

	// Append step to completed_steps
	var completedSteps []string
	if completedStepsRaw != nil {
		_ = json.Unmarshal(completedStepsRaw, &completedSteps)
	}
	// Check if already completed
	for _, s := range completedSteps {
		if s == stepID {
			c.JSON(http.StatusOK, gin.H{"message": "Step already completed", "execution_id": execID, "step_id": stepID})
			return
		}
	}
	completedSteps = append(completedSteps, stepID)
	newStepsJSON, _ := json.Marshal(completedSteps)

	// Get playbook steps to check if all required steps are done
	var stepsRaw []byte
	_ = h.pool.QueryRow(ctx,
		`SELECT steps FROM incident_playbooks WHERE id = $1`, playbookID,
	).Scan(&stepsRaw)

	type playbookStep struct {
		ID       string `json:"id"`
		Required bool   `json:"required"`
	}
	var allSteps []playbookStep
	if stepsRaw != nil {
		_ = json.Unmarshal(stepsRaw, &allSteps)
	}

	// Check if all required steps are done
	allRequiredDone := true
	completedSet := make(map[string]bool)
	for _, s := range completedSteps {
		completedSet[s] = true
	}
	for _, s := range allSteps {
		if s.Required && !completedSet[s.ID] {
			allRequiredDone = false
			break
		}
	}

	newStatus := status
	var completedAtArg interface{}
	if allRequiredDone && len(allSteps) > 0 {
		newStatus = "completed"
		completedAtArg = time.Now().UTC()
	}

	_, err = h.pool.Exec(ctx,
		`UPDATE playbook_executions SET completed_steps = $2, status = $3, completed_at = $4 WHERE id = $1`,
		execID, newStepsJSON, newStatus, completedAtArg,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update execution"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"execution_id":      execID,
		"step_id":           stepID,
		"status":            newStatus,
		"completed_steps":   completedSteps,
		"all_required_done": allRequiredDone,
	})
}

// ListExecutions returns recent playbook executions across all playbooks.
// GET /api/v1/admin/incident-playbooks/executions
func (h *IncidentPlaybookHandler) ListExecutions(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT e.id, e.playbook_id, COALESCE(p.name, e.playbook_id::text), e.status, e.current_step, e.started_at, e.completed_at
		FROM playbook_executions e
		LEFT JOIN incident_playbooks p ON p.id = e.playbook_id
		ORDER BY e.created_at DESC LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"executions": []any{}})
		return
	}
	defer rows.Close()

	type Exec struct {
		ID           string  `json:"id"`
		PlaybookID   string  `json:"playbook_id"`
		PlaybookName string  `json:"playbook_name"`
		Status       string  `json:"status"`
		CurrentStep  int     `json:"current_step"`
		StartedAt    string  `json:"started_at"`
		CompletedAt  *string `json:"completed_at"`
	}
	var list []Exec
	for rows.Next() {
		var e Exec
		var startedAt time.Time
		var completedAt *time.Time
		if err := rows.Scan(&e.ID, &e.PlaybookID, &e.PlaybookName, &e.Status, &e.CurrentStep, &startedAt, &completedAt); err != nil {
			continue
		}
		e.StartedAt = startedAt.UTC().Format(time.RFC3339)
		if completedAt != nil {
			s := completedAt.UTC().Format(time.RFC3339)
			e.CompletedAt = &s
		}
		list = append(list, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Exec{}
	}
	c.JSON(http.StatusOK, gin.H{"executions": list})
}
