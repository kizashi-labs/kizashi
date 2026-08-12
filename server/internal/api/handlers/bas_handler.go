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
)

// BASHandler handles Breach & Attack Simulation endpoints.
type BASHandler struct {
	pool *pgxpool.Pool
}

// NewBASHandler creates a new BASHandler.
func NewBASHandler(pool *pgxpool.Pool) *BASHandler {
	return &BASHandler{pool: pool}
}

func (h *BASHandler) checkScenariosTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='bas_scenarios')`).Scan(&exists)
	return err == nil && exists
}

func (h *BASHandler) checkRunsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='bas_runs')`).Scan(&exists)
	return err == nil && exists
}

// ListScenarios returns all BAS scenarios.
// GET /api/v1/admin/bas/scenarios
func (h *BASHandler) ListScenarios(c *gin.Context) {
	if !h.checkScenariosTable(c) {
		c.JSON(http.StatusOK, gin.H{"scenarios": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description, scenario_type, mitre_tactics, mitre_techniques,
		        difficulty, estimated_duration_min, is_active, created_at
		 FROM bas_scenarios ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type Scenario struct {
		ID                   string          `json:"id"`
		Name                 string          `json:"name"`
		Description          *string         `json:"description"`
		ScenarioType         string          `json:"scenario_type"`
		MitreTactics         json.RawMessage `json:"mitre_tactics"`
		MitreTechniques      json.RawMessage `json:"mitre_techniques"`
		Difficulty           string          `json:"difficulty"`
		EstimatedDurationMin int             `json:"estimated_duration_min"`
		IsActive             bool            `json:"is_active"`
		CreatedAt            time.Time       `json:"created_at"`
	}
	var scenarios []Scenario
	for rows.Next() {
		var s Scenario
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.ScenarioType,
			&s.MitreTactics, &s.MitreTechniques, &s.Difficulty,
			&s.EstimatedDurationMin, &s.IsActive, &s.CreatedAt); err != nil {
			continue
		}
		scenarios = append(scenarios, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if scenarios == nil {
		scenarios = []Scenario{}
	}
	c.JSON(http.StatusOK, gin.H{"scenarios": scenarios, "total": len(scenarios)})
}

// CreateScenario creates a new BAS scenario.
// POST /api/v1/admin/bas/scenarios
func (h *BASHandler) CreateScenario(c *gin.Context) {
	if !h.checkScenariosTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "bas_scenarios table not ready"})
		return
	}
	var in struct {
		Name                 string          `json:"name" binding:"required"`
		Description          *string         `json:"description"`
		ScenarioType         string          `json:"scenario_type" binding:"required"`
		MitreTactics         json.RawMessage `json:"mitre_tactics"`
		MitreTechniques      json.RawMessage `json:"mitre_techniques"`
		Difficulty           string          `json:"difficulty"`
		EstimatedDurationMin int             `json:"estimated_duration_min"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.MitreTactics) == 0 {
		in.MitreTactics = json.RawMessage(`[]`)
	}
	if len(in.MitreTechniques) == 0 {
		in.MitreTechniques = json.RawMessage(`[]`)
	}
	if in.Difficulty == "" {
		in.Difficulty = "medium"
	}
	if in.EstimatedDurationMin <= 0 {
		in.EstimatedDurationMin = 30
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO bas_scenarios (name, description, scenario_type, mitre_tactics, mitre_techniques,
		  difficulty, estimated_duration_min)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		in.Name, in.Description, in.ScenarioType, in.MitreTactics, in.MitreTechniques,
		in.Difficulty, in.EstimatedDurationMin,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "scenario created"})
}

// UpdateScenario updates an existing BAS scenario.
// PUT /api/v1/admin/bas/scenarios/:id
func (h *BASHandler) UpdateScenario(c *gin.Context) {
	if !h.checkScenariosTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "bas_scenarios table not ready"})
		return
	}
	id := c.Param("id")
	var in struct {
		Name                 *string         `json:"name"`
		Description          *string         `json:"description"`
		ScenarioType         *string         `json:"scenario_type"`
		MitreTactics         json.RawMessage `json:"mitre_tactics"`
		MitreTechniques      json.RawMessage `json:"mitre_techniques"`
		Difficulty           *string         `json:"difficulty"`
		EstimatedDurationMin *int            `json:"estimated_duration_min"`
		IsActive             *bool           `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE bas_scenarios SET
		   name = COALESCE($2, name),
		   description = COALESCE($3, description),
		   scenario_type = COALESCE($4, scenario_type),
		   mitre_tactics = COALESCE($5::jsonb, mitre_tactics),
		   mitre_techniques = COALESCE($6::jsonb, mitre_techniques),
		   difficulty = COALESCE($7, difficulty),
		   estimated_duration_min = COALESCE($8, estimated_duration_min),
		   is_active = COALESCE($9, is_active)
		 WHERE id = $1`,
		id, in.Name, in.Description, in.ScenarioType,
		basNullableJSON(in.MitreTactics), basNullableJSON(in.MitreTechniques),
		in.Difficulty, in.EstimatedDurationMin, in.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "scenario not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// DeleteScenario removes a BAS scenario.
// DELETE /api/v1/admin/bas/scenarios/:id
func (h *BASHandler) DeleteScenario(c *gin.Context) {
	if !h.checkScenariosTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "bas_scenarios table not ready"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM bas_scenarios WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "scenario not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// ListRuns returns BAS runs, optionally filtered.
// GET /api/v1/admin/bas/runs
func (h *BASHandler) ListRuns(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusOK, gin.H{"runs": []interface{}{}, "total": 0})
		return
	}
	scenarioID := c.Query("scenario_id")
	status := c.Query("status")
	ctx := c.Request.Context()
	query := `SELECT id, scenario_id, target_scope, status, detection_rate, prevention_rate,
	                 steps_total, steps_detected, steps_prevented, findings,
	                 started_at, completed_at, created_at
	          FROM bas_runs WHERE 1=1`
	args := []interface{}{}
	i := 1
	if scenarioID != "" {
		query += " AND scenario_id = $" + strconv.Itoa(i)
		args = append(args, scenarioID)
		i++
	}
	if status != "" {
		query += " AND status = $" + strconv.Itoa(i)
		args = append(args, status)
		i++
	}
	_ = i
	query += " ORDER BY created_at DESC LIMIT 100"
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type Run struct {
		ID             string          `json:"id"`
		ScenarioID     string          `json:"scenario_id"`
		TargetScope    json.RawMessage `json:"target_scope"`
		Status         string          `json:"status"`
		DetectionRate  *float64        `json:"detection_rate"`
		PreventionRate *float64        `json:"prevention_rate"`
		StepsTotal     int             `json:"steps_total"`
		StepsDetected  int             `json:"steps_detected"`
		StepsPrevented int             `json:"steps_prevented"`
		Findings       json.RawMessage `json:"findings"`
		StartedAt      *time.Time      `json:"started_at"`
		CompletedAt    *time.Time      `json:"completed_at"`
		CreatedAt      time.Time       `json:"created_at"`
	}
	var runs []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ScenarioID, &r.TargetScope, &r.Status,
			&r.DetectionRate, &r.PreventionRate,
			&r.StepsTotal, &r.StepsDetected, &r.StepsPrevented,
			&r.Findings, &r.StartedAt, &r.CompletedAt, &r.CreatedAt); err != nil {
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

// StartRun creates a BAS run and executes it asynchronously.
// POST /api/v1/admin/bas/runs
func (h *BASHandler) StartRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "bas_runs table not ready"})
		return
	}
	var in struct {
		ScenarioID  string          `json:"scenario_id" binding:"required"`
		TargetScope json.RawMessage `json:"target_scope"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.TargetScope) == 0 {
		in.TargetScope = json.RawMessage(`[]`)
	}
	ctx := c.Request.Context()
	var runID string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO bas_runs (scenario_id, target_scope, status) VALUES ($1,$2,'pending') RETURNING id`,
		in.ScenarioID, in.TargetScope,
	).Scan(&runID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	// Simulate run asynchronously
	runCtx, runCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	go func() {
		defer runCancel()
		h.simulateRun(runCtx, runID)
	}()
	c.JSON(http.StatusCreated, gin.H{"id": runID, "status": "pending"})
}

func (h *BASHandler) simulateRun(ctx context.Context, runID string) {
	now := time.Now().UTC()
	_, _ = h.pool.Exec(ctx,
		`UPDATE bas_runs SET status='completed', started_at=$2, completed_at=$2,
		  detection_rate=0, prevention_rate=0,
		  steps_total=0, steps_detected=0, steps_prevented=0
		 WHERE id=$1`,
		runID, now)
}

// GetRun returns a single BAS run by ID.
// GET /api/v1/admin/bas/runs/:id
func (h *BASHandler) GetRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	type Run struct {
		ID             string          `json:"id"`
		ScenarioID     string          `json:"scenario_id"`
		TargetScope    json.RawMessage `json:"target_scope"`
		Status         string          `json:"status"`
		DetectionRate  *float64        `json:"detection_rate"`
		PreventionRate *float64        `json:"prevention_rate"`
		StepsTotal     int             `json:"steps_total"`
		StepsDetected  int             `json:"steps_detected"`
		StepsPrevented int             `json:"steps_prevented"`
		Findings       json.RawMessage `json:"findings"`
		StartedAt      *time.Time      `json:"started_at"`
		CompletedAt    *time.Time      `json:"completed_at"`
		CreatedAt      time.Time       `json:"created_at"`
	}
	var r Run
	err := h.pool.QueryRow(ctx,
		`SELECT id, scenario_id, target_scope, status, detection_rate, prevention_rate,
		        steps_total, steps_detected, steps_prevented, findings,
		        started_at, completed_at, created_at
		 FROM bas_runs WHERE id=$1`, id,
	).Scan(&r.ID, &r.ScenarioID, &r.TargetScope, &r.Status,
		&r.DetectionRate, &r.PreventionRate,
		&r.StepsTotal, &r.StepsDetected, &r.StepsPrevented,
		&r.Findings, &r.StartedAt, &r.CompletedAt, &r.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// CancelRun cancels a pending or running BAS run.
// POST /api/v1/admin/bas/runs/:id/cancel
func (h *BASHandler) CancelRun(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE bas_runs SET status='cancelled' WHERE id=$1 AND status IN ('pending','running')`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found or not cancellable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "cancelled"})
}

// GetStats returns BAS statistics.
// GET /api/v1/admin/bas/stats
func (h *BASHandler) GetStats(c *gin.Context) {
	if !h.checkRunsTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"runs_by_status":      gin.H{},
			"avg_detection_rate":  0,
			"avg_prevention_rate": 0,
			"top_scenarios":       []interface{}{},
		})
		return
	}
	ctx := c.Request.Context()
	// Runs by status
	statusRows, err := h.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM bas_runs GROUP BY status`)
	runsByStatus := map[string]int{}
	if err == nil {
		defer statusRows.Close()
		for statusRows.Next() {
			var st string
			var cnt int
			if scanErr := statusRows.Scan(&st, &cnt); scanErr == nil {
				runsByStatus[st] = cnt
			}
		}
		if err := statusRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	// Avg detection/prevention rates
	var avgDetection, avgPrevention float64
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(detection_rate),0), COALESCE(AVG(prevention_rate),0)
		 FROM bas_runs WHERE status='completed'`,
	).Scan(&avgDetection, &avgPrevention)
	// Top scenarios by run count
	type TopScenario struct {
		ScenarioID string  `json:"scenario_id"`
		Name       string  `json:"name"`
		RunCount   int     `json:"run_count"`
		AvgDetect  float64 `json:"avg_detection_rate"`
	}
	topRows, topErr := h.pool.Query(ctx,
		`SELECT r.scenario_id, COALESCE(s.name,'unknown'), COUNT(*), COALESCE(AVG(r.detection_rate),0)
		 FROM bas_runs r LEFT JOIN bas_scenarios s ON s.id=r.scenario_id
		 GROUP BY r.scenario_id, s.name ORDER BY COUNT(*) DESC LIMIT 5`)
	var top []TopScenario
	if topErr == nil {
		defer topRows.Close()
		for topRows.Next() {
			var ts TopScenario
			if scanErr := topRows.Scan(&ts.ScenarioID, &ts.Name, &ts.RunCount, &ts.AvgDetect); scanErr == nil {
				top = append(top, ts)
			}
		}
		if err := topRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if top == nil {
		top = []TopScenario{}
	}
	c.JSON(http.StatusOK, gin.H{
		"runs_by_status":      runsByStatus,
		"avg_detection_rate":  avgDetection,
		"avg_prevention_rate": avgPrevention,
		"top_scenarios":       top,
	})
}

// basNullableJSON returns nil if the input is empty, else the raw JSON bytes.
func basNullableJSON(b json.RawMessage) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
