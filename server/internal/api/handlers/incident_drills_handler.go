package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentDrillsHandler serves CRUD for the /admin/incident-drills page —
// scheduling tabletop/technical exercises and recording their scorecards.
type IncidentDrillsHandler struct {
	pool *pgxpool.Pool
}

func NewIncidentDrillsHandler(pool *pgxpool.Pool) *IncidentDrillsHandler {
	return &IncidentDrillsHandler{pool: pool}
}

// parseScheduledAt accepts RFC3339 or the <input type="datetime-local"> formats
// the frontend emits. Falls back to now() when empty/unparseable.
func parseScheduledAt(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Now()
}

// List handles GET /api/v1/admin/incident-drills
func (h *IncidentDrillsHandler) List(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, drill_type, scenario, scenario_template, status,
		       scheduled_at, participants, facilitator, objectives,
		       is_timed, duration_minutes,
		       overall_score, key_findings, best_performer,
		       areas_for_improvement, score_breakdown
		FROM incident_drills
		WHERE tenant_id = $1::uuid
		ORDER BY scheduled_at DESC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	drills := []gin.H{}
	for rows.Next() {
		var (
			id, name, drillType, scenario, scenarioTemplate, status, facilitator string
			scheduledAt                                                          time.Time
			participants, objectives                                             json.RawMessage
			isTimed                                                              bool
			durationMinutes                                                      int
			overallScore                                                         *int
			keyFindings, bestPerformer                                           *string
			areasForImprovement, scoreBreakdown                                  json.RawMessage
		)
		if err := rows.Scan(&id, &name, &drillType, &scenario, &scenarioTemplate, &status,
			&scheduledAt, &participants, &facilitator, &objectives,
			&isTimed, &durationMinutes,
			&overallScore, &keyFindings, &bestPerformer,
			&areasForImprovement, &scoreBreakdown); err != nil {
			continue
		}
		var pArr []string
		_ = json.Unmarshal(participants, &pArr)
		drills = append(drills, gin.H{
			"id":                    id,
			"name":                  name,
			"drill_type":            drillType,
			"scenario":              scenario,
			"scenario_template":     scenarioTemplate,
			"status":                status,
			"scheduled_at":          scheduledAt,
			"participants":          participants,
			"participants_count":    len(pArr),
			"facilitator":           facilitator,
			"objectives":            objectives,
			"is_timed":              isTimed,
			"duration_minutes":      durationMinutes,
			"overall_score":         overallScore,
			"key_findings":          keyFindings,
			"best_performer":        bestPerformer,
			"areas_for_improvement": areasForImprovement,
			"score_breakdown":       scoreBreakdown,
		})
	}
	c.JSON(http.StatusOK, gin.H{"drills": drills})
}

// Create handles POST /api/v1/admin/incident-drills
func (h *IncidentDrillsHandler) Create(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	var req struct {
		Name             string   `json:"name"`
		DrillType        string   `json:"drill_type"`
		Scenario         string   `json:"scenario"`
		ScenarioTemplate string   `json:"scenario_template"`
		ScheduledAt      string   `json:"scheduled_at"`
		Participants     []string `json:"participants"`
		Facilitator      string   `json:"facilitator"`
		Objectives       []string `json:"objectives"`
		IsTimed          bool     `json:"is_timed"`
		DurationMinutes  int      `json:"duration_minutes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "訓練名は必須です"})
		return
	}
	if req.DrillType == "" {
		req.DrillType = "tabletop"
	}
	if req.ScenarioTemplate == "" {
		req.ScenarioTemplate = "custom"
	}
	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 60
	}
	if req.Participants == nil {
		req.Participants = []string{}
	}
	if req.Objectives == nil {
		req.Objectives = []string{}
	}
	scheduledAt := parseScheduledAt(req.ScheduledAt)
	participants, _ := json.Marshal(req.Participants)
	objectives, _ := json.Marshal(req.Objectives)

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO incident_drills
		    (tenant_id, name, drill_type, scenario, scenario_template, status,
		     scheduled_at, participants, facilitator, objectives, is_timed, duration_minutes)
		VALUES ($1::uuid, $2, $3, $4, $5, 'scheduled',
		        $6, $7::jsonb, $8, $9::jsonb, $10, $11)
		RETURNING id`,
		tenantID, req.Name, req.DrillType, req.Scenario, req.ScenarioTemplate,
		scheduledAt, participants, req.Facilitator, objectives, req.IsTimed, req.DurationMinutes).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                 id,
		"name":               req.Name,
		"drill_type":         req.DrillType,
		"scenario":           req.Scenario,
		"scenario_template":  req.ScenarioTemplate,
		"status":             "scheduled",
		"scheduled_at":       scheduledAt,
		"participants":       req.Participants,
		"participants_count": len(req.Participants),
		"facilitator":        req.Facilitator,
		"objectives":         req.Objectives,
		"is_timed":           req.IsTimed,
		"duration_minutes":   req.DurationMinutes,
	})
}

// Update handles PUT /api/v1/admin/incident-drills/:id — partial update used to
// record completion (status + scorecard) or edit a scheduled drill.
func (h *IncidentDrillsHandler) Update(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")
	id := c.Param("id")

	var req struct {
		Status              *string        `json:"status"`
		OverallScore        *int           `json:"overall_score"`
		KeyFindings         *string        `json:"key_findings"`
		BestPerformer       *string        `json:"best_performer"`
		AreasForImprovement []string       `json:"areas_for_improvement"`
		ScoreBreakdown      map[string]int `json:"score_breakdown"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// nil []byte encodes to SQL NULL, so COALESCE preserves the existing value
	// when a JSON field is omitted from the request.
	var areas, breakdown []byte
	if req.AreasForImprovement != nil {
		areas, _ = json.Marshal(req.AreasForImprovement)
	}
	if req.ScoreBreakdown != nil {
		breakdown, _ = json.Marshal(req.ScoreBreakdown)
	}

	ct, err := h.pool.Exec(ctx, `
		UPDATE incident_drills SET
			status                = COALESCE($3, status),
			overall_score         = COALESCE($4, overall_score),
			key_findings          = COALESCE($5, key_findings),
			best_performer        = COALESCE($6, best_performer),
			areas_for_improvement = COALESCE($7::jsonb, areas_for_improvement),
			score_breakdown       = COALESCE($8::jsonb, score_breakdown),
			updated_at            = NOW()
		WHERE id = $1::uuid AND tenant_id = $2::uuid`,
		id, tenantID, req.Status, req.OverallScore, req.KeyFindings, req.BestPerformer,
		areas, breakdown)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "訓練が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Delete handles DELETE /api/v1/admin/incident-drills/:id
func (h *IncidentDrillsHandler) Delete(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")
	id := c.Param("id")

	ct, err := h.pool.Exec(ctx,
		`DELETE FROM incident_drills WHERE id = $1::uuid AND tenant_id = $2::uuid`, id, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "訓練が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
