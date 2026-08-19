package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskRegisterHandler manages the risk register (CRUD for risks).
// GET/POST         /api/v1/admin/risk-register
// PUT/DELETE /:id  /api/v1/admin/risk-register/:id
type RiskRegisterHandler struct {
	pool *pgxpool.Pool
}

func NewRiskRegisterHandler(pool *pgxpool.Pool) *RiskRegisterHandler {
	return &RiskRegisterHandler{pool: pool}
}

func (h *RiskRegisterHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "risk_register")
}

type riskItem struct {
	ID                   string          `json:"id"`
	RiskID               string          `json:"risk_id"`
	Title                string          `json:"title"`
	Description          string          `json:"description"`
	Category             string          `json:"category"`
	ThreatSource         string          `json:"threat_source"`
	Vulnerability        string          `json:"vulnerability"`
	Likelihood           int             `json:"likelihood"`
	Impact               int             `json:"impact"`
	InherentRiskScore    int             `json:"inherent_risk_score"`
	Controls             json.RawMessage `json:"controls"`
	ControlEffectiveness int             `json:"control_effectiveness"`
	ResidualRiskScore    int             `json:"residual_risk_score"`
	RiskAppetite         string          `json:"risk_appetite"`
	Owner                string          `json:"owner"`
	LastReviewDate       string          `json:"last_review_date"`
	Status               string          `json:"status"`
	TreatmentPlan        json.RawMessage `json:"treatment_plan"`
	RiskHistory          json.RawMessage `json:"risk_history"`
	CreatedAt            string          `json:"created_at"`
}

// Allowed values for the risk_register CHECK constraints (mirror the migration).
var (
	validRiskAppetite = map[string]bool{"within": true, "exceeds": true, "at_limit": true}
	validRiskStatus   = map[string]bool{"active": true, "mitigated": true, "transferred": true, "accepted": true, "closed": true}
)

// validateRiskConstraints checks the constrained fields against the table's
// CHECK constraints and returns a client-facing message (empty when valid).
func validateRiskConstraints(likelihood, impact, controlEff int, appetite, status string) string {
	if likelihood < 1 || likelihood > 5 {
		return "likelihood must be between 1 and 5"
	}
	if impact < 1 || impact > 5 {
		return "impact must be between 1 and 5"
	}
	if controlEff < 0 || controlEff > 100 {
		return "control_effectiveness must be between 0 and 100"
	}
	if !validRiskAppetite[appetite] {
		return "risk_appetite must be one of: within, exceeds, at_limit"
	}
	if !validRiskStatus[status] {
		return "status must be one of: active, mitigated, transferred, accepted, closed"
	}
	return ""
}

// List returns all risks.
// GET /api/v1/admin/risk-register
func (h *RiskRegisterHandler) List(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, risk_id, title, description, category, threat_source, vulnerability,
		        likelihood, impact, inherent_risk_score,
		        COALESCE(controls,'[]'::jsonb), control_effectiveness, residual_risk_score,
		        risk_appetite, owner, last_review_date, status,
		        COALESCE(treatment_plan,'[]'::jsonb), COALESCE(risk_history,'[]'::jsonb),
		        created_at
		 FROM risk_register ORDER BY residual_risk_score DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list risks"})
		return
	}
	defer rows.Close()

	var risks []riskItem
	for rows.Next() {
		var r riskItem
		var lastReview, createdAt time.Time
		if err := rows.Scan(
			&r.ID, &r.RiskID, &r.Title, &r.Description, &r.Category,
			&r.ThreatSource, &r.Vulnerability, &r.Likelihood, &r.Impact,
			&r.InherentRiskScore, &r.Controls, &r.ControlEffectiveness,
			&r.ResidualRiskScore, &r.RiskAppetite, &r.Owner,
			&lastReview, &r.Status, &r.TreatmentPlan, &r.RiskHistory, &createdAt,
		); err != nil {
			continue
		}
		r.LastReviewDate = lastReview.Format("2006-01-02")
		r.CreatedAt = createdAt.Format(time.RFC3339)
		risks = append(risks, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list risks"})
		return
	}
	if risks == nil {
		risks = []riskItem{}
	}
	c.JSON(http.StatusOK, risks)
}

// Create creates a new risk entry.
// POST /api/v1/admin/risk-register
func (h *RiskRegisterHandler) Create(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Risk register table not available"})
		return
	}
	var body struct {
		RiskID        string `json:"risk_id"`
		Title         string `json:"title" binding:"required"`
		Description   string `json:"description"`
		Category      string `json:"category"`
		ThreatSource  string `json:"threat_source"`
		Vulnerability string `json:"vulnerability"`
		Likelihood    int    `json:"likelihood"`
		Impact        int    `json:"impact"`
		Owner         string `json:"owner"`
		Status        string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title is required"})
		return
	}
	if body.Status == "" {
		body.Status = "active"
	}
	// Validate the constrained fields up front. control_effectiveness and
	// risk_appetite are not part of Create's body — the table defaults (0 /
	// 'within') apply — so we validate against those defaults.
	if msg := validateRiskConstraints(body.Likelihood, body.Impact, 0, "within", body.Status); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	inherent := body.Likelihood * body.Impact
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO risk_register
		 (risk_id, title, description, category, threat_source, vulnerability,
		  likelihood, impact, inherent_risk_score, residual_risk_score, owner, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11) RETURNING id`,
		body.RiskID, body.Title, body.Description, body.Category,
		body.ThreatSource, body.Vulnerability, body.Likelihood, body.Impact,
		inherent, body.Owner, body.Status,
	).Scan(&id)
	if err != nil {
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid risk field values"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create risk"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Risk created"})
}

// Update updates a risk entry.
// PUT /api/v1/admin/risk-register/:id
func (h *RiskRegisterHandler) Update(c *gin.Context) {
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
		Title                string `json:"title"`
		Description          string `json:"description"`
		Category             string `json:"category"`
		ThreatSource         string `json:"threat_source"`
		Vulnerability        string `json:"vulnerability"`
		Likelihood           int    `json:"likelihood"`
		Impact               int    `json:"impact"`
		ControlEffectiveness int    `json:"control_effectiveness"`
		RiskAppetite         string `json:"risk_appetite"`
		Owner                string `json:"owner"`
		Status               string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Empty constrained fields fall back to the same defaults Create and the
	// table use, so a full-replace PUT that omits them does not trip the CHECK
	// constraints (which previously surfaced as a misleading "Risk not found").
	if body.Status == "" {
		body.Status = "active"
	}
	if body.RiskAppetite == "" {
		body.RiskAppetite = "within"
	}
	// Validate against the table CHECK constraints up front so invalid input
	// gets a clear 400 instead of an opaque DB error.
	if msg := validateRiskConstraints(body.Likelihood, body.Impact, body.ControlEffectiveness, body.RiskAppetite, body.Status); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	inherent := body.Likelihood * body.Impact
	residual := inherent - (inherent * body.ControlEffectiveness / 100)
	if residual < 0 {
		residual = 0
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE risk_register SET
		 title=$1, description=$2, category=$3, threat_source=$4, vulnerability=$5,
		 likelihood=$6, impact=$7, inherent_risk_score=$8, control_effectiveness=$9,
		 residual_risk_score=$10, risk_appetite=$11, owner=$12, status=$13
		 WHERE id=$14`,
		body.Title, body.Description, body.Category, body.ThreatSource, body.Vulnerability,
		body.Likelihood, body.Impact, inherent, body.ControlEffectiveness, residual,
		body.RiskAppetite, body.Owner, body.Status, id,
	)
	if err != nil {
		// Distinguish "client sent bad data" (400) from an unexpected DB fault
		// (500). Only a genuine zero-row update is "not found".
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid risk field values"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update risk"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Risk not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Risk updated"})
}

// Delete deletes a risk entry.
// DELETE /api/v1/admin/risk-register/:id
func (h *RiskRegisterHandler) Delete(c *gin.Context) {
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
	_, err := h.pool.Exec(ctx, `DELETE FROM risk_register WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete risk"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Risk deleted"})
}
