package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdversaryEmulationHandler manages adversary emulation plans and their
// execution records (MITRE ATT&CK based detection-capability assessment).
type AdversaryEmulationHandler struct {
	pool *pgxpool.Pool
}

// NewAdversaryEmulationHandler creates a new AdversaryEmulationHandler.
func NewAdversaryEmulationHandler(pool *pgxpool.Pool) *AdversaryEmulationHandler {
	return &AdversaryEmulationHandler{pool: pool}
}

// ── Types (mirror the frontend's EmulationPlan / ExecutionResult) ──────────────

type aeTechnique struct {
	ID                   string   `json:"id"`
	MitreID              string   `json:"mitre_id"`
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	DetectionOpportunity string   `json:"detection_opportunity"`
	ProcedureSteps       []string `json:"procedure_steps"`
}

type aePhase struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Order       int           `json:"order"`
	Description string        `json:"description"`
	Techniques  []aeTechnique `json:"techniques"`
}

type aeActorProfile struct {
	Name           string   `json:"name"`
	Motivation     string   `json:"motivation"`
	Sophistication string   `json:"sophistication"`
	Origin         string   `json:"origin"`
	KnownCampaigns []string `json:"known_campaigns"`
}

type aePrecondition struct {
	Label   string `json:"label"`
	Checked bool   `json:"checked"`
}

type emulationPlan struct {
	ID                 string           `json:"id"`
	PlanName           string           `json:"plan_name"`
	ThreatActorBasedOn string           `json:"threat_actor_based_on"`
	ActorProfile       aeActorProfile   `json:"actor_profile"`
	Scope              string           `json:"scope"`
	Status             string           `json:"status"`
	CreatedBy          string           `json:"created_by"`
	LastExecuted       *string          `json:"last_executed"`
	TechniqueCount     int              `json:"technique_count"`
	Phases             []aePhase        `json:"phases"`
	TargetSystems      []string         `json:"target_systems"`
	ExcludedSystems    []string         `json:"excluded_systems"`
	TimeWindow         string           `json:"time_window"`
	RulesOfEngagement  string           `json:"rules_of_engagement"`
	Preconditions      []aePrecondition `json:"preconditions"`
	CreatedAt          string           `json:"created_at"`
}

type aeTechResult struct {
	MitreID       string `json:"mitre_id"`
	TechniqueName string `json:"technique_name"`
	Result        string `json:"result"`
	Notes         string `json:"notes"`
}

type aePhaseResult struct {
	PhaseName  string         `json:"phase_name"`
	Techniques []aeTechResult `json:"techniques"`
}

type aeGap struct {
	MitreID        string `json:"mitre_id"`
	TechniqueName  string `json:"technique_name"`
	Recommendation string `json:"recommendation"`
}

type emulationExecution struct {
	ID                    string          `json:"id"`
	PlanID                string          `json:"plan_id"`
	PlanName              string          `json:"plan_name"`
	ExecutedAt            string          `json:"executed_at"`
	ExecutedBy            string          `json:"executed_by"`
	DurationMinutes       int             `json:"duration_minutes"`
	PhasesCompleted       int             `json:"phases_completed"`
	PhasesTotal           int             `json:"phases_total"`
	DetectionsCount       int             `json:"detections_count"`
	MissedDetectionsCount int             `json:"missed_detections_count"`
	DetectionRate         float64         `json:"detection_rate"`
	PhaseResults          []aePhaseResult `json:"phase_results"`
	GapAnalysis           []aeGap         `json:"gap_analysis"`
	Notes                 string          `json:"notes"`
}

// ── Plans ──────────────────────────────────────────────────────────────────────

// ListPlans returns all emulation plans (newest first) as a JSON array.
// GET /api/v1/admin/adversary-emulation
func (h *AdversaryEmulationHandler) ListPlans(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id, plan_name, threat_actor_based_on, actor_profile, scope, status,
		       created_by, last_executed, phases, target_systems, excluded_systems,
		       time_window, rules_of_engagement, preconditions, created_at
		FROM emulation_plans ORDER BY created_at DESC`)
	if err != nil {
		ReadFailure(c, err, []emulationPlan{})
		return
	}
	defer rows.Close()

	plans := []emulationPlan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			continue
		}
		plans = append(plans, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListPlans: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []emulationPlan{})
		return
	}
	c.JSON(http.StatusOK, plans)
}

// rowScanner is satisfied by both pgx.Rows and pgx.Row.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPlan(row rowScanner) (emulationPlan, error) {
	var p emulationPlan
	var lastExec *time.Time
	var createdAt time.Time
	if err := row.Scan(
		&p.ID, &p.PlanName, &p.ThreatActorBasedOn, &p.ActorProfile, &p.Scope, &p.Status,
		&p.CreatedBy, &lastExec, &p.Phases, &p.TargetSystems, &p.ExcludedSystems,
		&p.TimeWindow, &p.RulesOfEngagement, &p.Preconditions, &createdAt,
	); err != nil {
		return p, err
	}
	if lastExec != nil {
		s := lastExec.UTC().Format(time.RFC3339)
		p.LastExecuted = &s
	}
	p.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	normalizePlan(&p)
	return p, nil
}

// normalizePlan ensures slices are non-nil (clean JSON arrays) and recomputes
// the derived technique_count.
func normalizePlan(p *emulationPlan) {
	if p.Phases == nil {
		p.Phases = []aePhase{}
	}
	if p.TargetSystems == nil {
		p.TargetSystems = []string{}
	}
	if p.ExcludedSystems == nil {
		p.ExcludedSystems = []string{}
	}
	if p.Preconditions == nil {
		p.Preconditions = []aePrecondition{}
	}
	if p.ActorProfile.KnownCampaigns == nil {
		p.ActorProfile.KnownCampaigns = []string{}
	}
	count := 0
	for _, ph := range p.Phases {
		count += len(ph.Techniques)
	}
	p.TechniqueCount = count
}

// CreatePlan creates a new emulation plan.
// POST /api/v1/admin/adversary-emulation
func (h *AdversaryEmulationHandler) CreatePlan(c *gin.Context) {
	var body emulationPlan
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.PlanName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan_name is required"})
		return
	}
	if body.Status == "" {
		body.Status = "draft"
	}
	if body.CreatedBy == "" {
		if u := c.GetString("username"); u != "" {
			body.CreatedBy = u
		} else {
			body.CreatedBy = "admin"
		}
	}
	normalizePlan(&body)

	actorProfile, _ := json.Marshal(body.ActorProfile)
	phases, _ := json.Marshal(body.Phases)
	targets, _ := json.Marshal(body.TargetSystems)
	excluded, _ := json.Marshal(body.ExcludedSystems)
	preconds, _ := json.Marshal(body.Preconditions)

	var id string
	var createdAt time.Time
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO emulation_plans
		    (plan_name, threat_actor_based_on, actor_profile, scope, status, created_by,
		     phases, target_systems, excluded_systems, time_window, rules_of_engagement, preconditions)
		VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12::jsonb)
		RETURNING id, created_at`,
		body.PlanName, body.ThreatActorBasedOn, actorProfile, body.Scope, body.Status, body.CreatedBy,
		phases, targets, excluded, body.TimeWindow, body.RulesOfEngagement, preconds,
	).Scan(&id, &createdAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	body.ID = id
	body.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	c.JSON(http.StatusCreated, body)
}

// DeletePlan removes an emulation plan (and its executions via cascade).
// DELETE /api/v1/admin/adversary-emulation/:id
func (h *AdversaryEmulationHandler) DeletePlan(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `DELETE FROM emulation_plans WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "plan not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// ── Executions ─────────────────────────────────────────────────────────────────

// ListExecutions returns all execution records (newest first) as a JSON array.
// GET /api/v1/admin/adversary-emulation/executions
func (h *AdversaryEmulationHandler) ListExecutions(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id, plan_id, plan_name, executed_at, executed_by, duration_minutes,
		       phases_completed, phases_total, detections_count, missed_detections_count,
		       detection_rate, phase_results, gap_analysis, notes
		FROM emulation_executions ORDER BY executed_at DESC`)
	if err != nil {
		ReadFailure(c, err, []emulationExecution{})
		return
	}
	defer rows.Close()

	results := []emulationExecution{}
	for rows.Next() {
		var e emulationExecution
		var executedAt time.Time
		if err := rows.Scan(
			&e.ID, &e.PlanID, &e.PlanName, &executedAt, &e.ExecutedBy, &e.DurationMinutes,
			&e.PhasesCompleted, &e.PhasesTotal, &e.DetectionsCount, &e.MissedDetectionsCount,
			&e.DetectionRate, &e.PhaseResults, &e.GapAnalysis, &e.Notes,
		); err != nil {
			continue
		}
		e.ExecutedAt = executedAt.UTC().Format(time.RFC3339)
		if e.PhaseResults == nil {
			e.PhaseResults = []aePhaseResult{}
		}
		if e.GapAnalysis == nil {
			e.GapAnalysis = []aeGap{}
		}
		results = append(results, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListExecutions: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []emulationExecution{})
		return
	}
	c.JSON(http.StatusOK, results)
}

// CreateExecution records an execution result for a plan and stamps the plan's
// last_executed time.
// POST /api/v1/admin/adversary-emulation/executions
func (h *AdversaryEmulationHandler) CreateExecution(c *gin.Context) {
	var body emulationExecution
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.PlanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan_id is required"})
		return
	}
	if body.ExecutedBy == "" {
		if u := c.GetString("username"); u != "" {
			body.ExecutedBy = u
		} else {
			body.ExecutedBy = "admin"
		}
	}
	if body.PhaseResults == nil {
		body.PhaseResults = []aePhaseResult{}
	}
	if body.GapAnalysis == nil {
		body.GapAnalysis = []aeGap{}
	}

	// Resolve the plan name (and validate the plan exists).
	var planName string
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT plan_name FROM emulation_plans WHERE id=$1`, body.PlanID).Scan(&planName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan not found"})
		return
	}
	body.PlanName = planName

	phaseResults, _ := json.Marshal(body.PhaseResults)
	gapAnalysis, _ := json.Marshal(body.GapAnalysis)

	var id string
	var executedAt time.Time
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO emulation_executions
		    (plan_id, plan_name, executed_by, duration_minutes, phases_completed, phases_total,
		     detections_count, missed_detections_count, detection_rate, phase_results, gap_analysis, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12)
		RETURNING id, executed_at`,
		body.PlanID, body.PlanName, body.ExecutedBy, body.DurationMinutes, body.PhasesCompleted,
		body.PhasesTotal, body.DetectionsCount, body.MissedDetectionsCount, body.DetectionRate,
		phaseResults, gapAnalysis, body.Notes,
	).Scan(&id, &executedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Stamp the plan's last_executed time (best effort).
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE emulation_plans SET last_executed=$1 WHERE id=$2`, executedAt, body.PlanID); !WriteOK(c, err) {
		return
	}

	body.ID = id
	body.ExecutedAt = executedAt.UTC().Format(time.RFC3339)
	c.JSON(http.StatusCreated, body)
}
