package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VendorRiskHandler manages third-party/supply chain risk.
type VendorRiskHandler struct {
	pool *pgxpool.Pool
}

// NewVendorRiskHandler creates a new VendorRiskHandler.
func NewVendorRiskHandler(pool *pgxpool.Pool) *VendorRiskHandler {
	return &VendorRiskHandler{pool: pool}
}

func vendorRiskTier(score int) string {
	switch {
	case score <= 30:
		return "low"
	case score <= 60:
		return "medium"
	case score <= 80:
		return "high"
	default:
		return "critical"
	}
}

// ListVendors GET /vendor-risk/vendors
func (h *VendorRiskHandler) ListVendors(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	riskTier := c.Query("risk_tier")
	status := c.Query("status")

	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1
	if riskTier != "" {
		where += " AND risk_tier = $" + strconv.Itoa(idx)
		args = append(args, riskTier)
		idx++
	}
	if status != "" {
		where += " AND status = $" + strconv.Itoa(idx)
		args = append(args, status)
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	_ = h.pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM third_party_vendors "+where, countArgs...).Scan(&total)

	args = append(args, limit, offset)
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, category, website, contact_email, risk_score, risk_tier,
		        last_assessment_at, next_assessment_due, status, notes, created_at, updated_at
		 FROM third_party_vendors `+where+
			` ORDER BY risk_score DESC LIMIT $`+strconv.Itoa(idx)+` OFFSET $`+strconv.Itoa(idx+1),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list vendors"})
		return
	}
	defer rows.Close()

	type Vendor struct {
		ID                string     `json:"id"`
		Name              string     `json:"name"`
		Category          string     `json:"category"`
		Website           string     `json:"website"`
		ContactEmail      string     `json:"contact_email"`
		RiskScore         int        `json:"risk_score"`
		RiskTier          string     `json:"risk_tier"`
		LastAssessmentAt  *time.Time `json:"last_assessment_at"`
		NextAssessmentDue *time.Time `json:"next_assessment_due"`
		Status            string     `json:"status"`
		Notes             string     `json:"notes"`
		CreatedAt         time.Time  `json:"created_at"`
		UpdatedAt         time.Time  `json:"updated_at"`
	}

	vendors := []Vendor{}
	for rows.Next() {
		var v Vendor
		if err := rows.Scan(&v.ID, &v.Name, &v.Category, &v.Website, &v.ContactEmail,
			&v.RiskScore, &v.RiskTier, &v.LastAssessmentAt, &v.NextAssessmentDue,
			&v.Status, &v.Notes, &v.CreatedAt, &v.UpdatedAt); err != nil {
			continue
		}
		vendors = append(vendors, v)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{"data": vendors, "total": total})
}

// GetVendor GET /vendor-risk/vendors/:id
func (h *VendorRiskHandler) GetVendor(c *gin.Context) {
	id := c.Param("id")

	type Vendor struct {
		ID                string     `json:"id"`
		Name              string     `json:"name"`
		Category          string     `json:"category"`
		Website           string     `json:"website"`
		ContactEmail      string     `json:"contact_email"`
		RiskScore         int        `json:"risk_score"`
		RiskTier          string     `json:"risk_tier"`
		LastAssessmentAt  *time.Time `json:"last_assessment_at"`
		NextAssessmentDue *time.Time `json:"next_assessment_due"`
		Status            string     `json:"status"`
		Notes             string     `json:"notes"`
		CreatedAt         time.Time  `json:"created_at"`
		UpdatedAt         time.Time  `json:"updated_at"`
	}
	var v Vendor
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, category, website, contact_email, risk_score, risk_tier,
		        last_assessment_at, next_assessment_due, status, notes, created_at, updated_at
		 FROM third_party_vendors WHERE id = $1`, id).
		Scan(&v.ID, &v.Name, &v.Category, &v.Website, &v.ContactEmail,
			&v.RiskScore, &v.RiskTier, &v.LastAssessmentAt, &v.NextAssessmentDue,
			&v.Status, &v.Notes, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vendor not found"})
		return
	}

	// Fetch assessment history
	type Assessment struct {
		ID           string          `json:"id"`
		AssessorID   *string         `json:"assessor_id"`
		Scores       json.RawMessage `json:"scores"`
		OverallScore int             `json:"overall_score"`
		Findings     string          `json:"findings"`
		Status       string          `json:"status"`
		AssessedAt   time.Time       `json:"assessed_at"`
	}
	aRows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, assessor_id, scores, overall_score, findings, status, assessed_at
		 FROM vendor_assessments WHERE vendor_id = $1 ORDER BY assessed_at DESC LIMIT 10`, id)
	assessments := []Assessment{}
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var a Assessment
			if err := aRows.Scan(&a.ID, &a.AssessorID, &a.Scores, &a.OverallScore,
				&a.Findings, &a.Status, &a.AssessedAt); err == nil {
				assessments = append(assessments, a)
			}
		}
		if err := aRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": v, "assessments": assessments})
}

// CreateVendor POST /vendor-risk/vendors
func (h *VendorRiskHandler) CreateVendor(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		Category     string `json:"category"`
		Website      string `json:"website"`
		ContactEmail string `json:"contact_email"`
		Status       string `json:"status"`
		Notes        string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Category == "" {
		req.Category = "software"
	}
	if req.Status == "" {
		req.Status = "active"
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO third_party_vendors (name, category, website, contact_email, status, notes)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.Name, req.Category, req.Website, req.ContactEmail, req.Status, req.Notes).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create vendor"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "vendor created", "id": id})
}

// UpdateVendor PUT /vendor-risk/vendors/:id
func (h *VendorRiskHandler) UpdateVendor(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name         *string `json:"name"`
		Category     *string `json:"category"`
		Website      *string `json:"website"`
		ContactEmail *string `json:"contact_email"`
		Status       *string `json:"status"`
		Notes        *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ct, err := h.pool.Exec(c.Request.Context(),
		`UPDATE third_party_vendors
		 SET name = COALESCE($2, name),
		     category = COALESCE($3, category),
		     website = COALESCE($4, website),
		     contact_email = COALESCE($5, contact_email),
		     status = COALESCE($6, status),
		     notes = COALESCE($7, notes),
		     updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Category, req.Website, req.ContactEmail, req.Status, req.Notes)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "vendor not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "vendor updated"})
}

// DeleteVendor DELETE /vendor-risk/vendors/:id
func (h *VendorRiskHandler) DeleteVendor(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM third_party_vendors WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "vendor not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "vendor deleted"})
}

// CreateAssessment POST /vendor-risk/vendors/:id/assessments
func (h *VendorRiskHandler) CreateAssessment(c *gin.Context) {
	vendorID := c.Param("id")

	var req struct {
		Scores   map[string]float64 `json:"scores" binding:"required"`
		Findings string             `json:"findings"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scores is required"})
		return
	}

	// Compute overall_score as average of all score values
	var sum float64
	count := 0
	for _, v := range req.Scores {
		sum += v
		count++
	}
	overallScore := 0
	if count > 0 {
		overallScore = int(sum / float64(count))
	}

	riskTier := vendorRiskTier(overallScore)

	assessorID, _ := c.Get("user_id")
	assessorIDStr, _ := assessorID.(string)

	scoresJSON, _ := json.Marshal(req.Scores)

	var assessID string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO vendor_assessments (vendor_id, assessor_id, scores, overall_score, findings, status)
		 VALUES ($1, $2, $3, $4, $5, 'completed') RETURNING id`,
		vendorID, assessorIDStr, string(scoresJSON), overallScore, req.Findings).Scan(&assessID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create assessment"})
		return
	}

	// Update vendor risk_score, risk_tier, last_assessment_at
	_, _ = h.pool.Exec(c.Request.Context(),
		`UPDATE third_party_vendors
		 SET risk_score = $2, risk_tier = $3, last_assessment_at = NOW(), updated_at = NOW()
		 WHERE id = $1`,
		vendorID, overallScore, riskTier)

	c.JSON(http.StatusCreated, gin.H{
		"message":       "assessment created",
		"id":            assessID,
		"overall_score": overallScore,
		"risk_tier":     riskTier,
	})
}

// ListAssessments returns all vendor assessments.
// GET /api/v1/vendor-risk/assessments
func (h *VendorRiskHandler) ListAssessments(c *gin.Context) {
	ctx := c.Request.Context()

	type Assessment struct {
		ID           string    `json:"id"`
		VendorID     string    `json:"vendor_id"`
		VendorName   string    `json:"vendor_name"`
		OverallScore int       `json:"overall_score"`
		Status       string    `json:"status"`
		Findings     string    `json:"findings"`
		AssessedAt   time.Time `json:"assessed_at"`
	}

	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='vendor_assessments')`).Scan(&exists)
	if !exists {
		c.JSON(http.StatusOK, []Assessment{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT va.id::text, va.vendor_id::text, COALESCE(v.name,''), va.overall_score,
		       va.status, COALESCE(va.findings,''), va.assessed_at
		FROM vendor_assessments va
		LEFT JOIN third_party_vendors v ON v.id = va.vendor_id
		ORDER BY va.assessed_at DESC LIMIT 200`)
	if err != nil {
		c.JSON(http.StatusOK, []Assessment{})
		return
	}
	defer rows.Close()

	var items []Assessment
	for rows.Next() {
		var a Assessment
		if rows.Scan(&a.ID, &a.VendorID, &a.VendorName, &a.OverallScore, &a.Status, &a.Findings, &a.AssessedAt) == nil {
			items = append(items, a)
		}
	}
	if items == nil {
		items = []Assessment{}
	}
	c.JSON(http.StatusOK, items)
}

// GetStats GET /vendor-risk/stats
func (h *VendorRiskHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	type TierCount struct {
		Tier  string `json:"tier"`
		Count int    `json:"count"`
	}
	rows, err := h.pool.Query(ctx,
		`SELECT risk_tier, COUNT(*) FROM third_party_vendors GROUP BY risk_tier`)
	tierCounts := []TierCount{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tc TierCount
			if err := rows.Scan(&tc.Tier, &tc.Count); err == nil {
				tierCounts = append(tierCounts, tc)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var avgRiskScore float64
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(risk_score), 0) FROM third_party_vendors`).Scan(&avgRiskScore)

	var assessmentsDueThisMonth int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM third_party_vendors
		 WHERE next_assessment_due >= DATE_TRUNC('month', NOW())
		   AND next_assessment_due < DATE_TRUNC('month', NOW()) + INTERVAL '1 month'`).
		Scan(&assessmentsDueThisMonth)

	c.JSON(http.StatusOK, gin.H{
		"by_tier":                    tierCounts,
		"avg_risk_score":             avgRiskScore,
		"assessments_due_this_month": assessmentsDueThisMonth,
	})
}
