package handlers

// Mutations for the /admin/capacity-planning page.
// Kept in a separate file from the read-only handlers to keep concerns
// split: reads are hot-path and well-audited, writes are rare admin edits.
// Each table follows the same shape (POST create, PUT update, DELETE remove)
// except singletons (storage metrics, planning targets) which expose PUT only.

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ─── Singletons ────────────────────────────────────────────────────

// UpdateStorage upserts the single cp_storage_metrics row. Using ON CONFLICT
// instead of UPDATE lets the endpoint work even if the seed never ran.
func (h *CapacityPlanningHandler) UpdateStorage(c *gin.Context) {
	var req struct {
		UsedTB         float64 `json:"used_tb"`
		TotalTB        float64 `json:"total_tb"`
		Projected6MTB  float64 `json:"projected_6m_tb"`
		Projected12MTB float64 `json:"projected_12m_tb"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		INSERT INTO cp_storage_metrics (id, used_tb, total_tb, projected_6m_tb, projected_12m_tb, updated_at)
		VALUES (1, $1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			used_tb = EXCLUDED.used_tb,
			total_tb = EXCLUDED.total_tb,
			projected_6m_tb = EXCLUDED.projected_6m_tb,
			projected_12m_tb = EXCLUDED.projected_12m_tb,
			updated_at = NOW()`,
		req.UsedTB, req.TotalTB, req.Projected6MTB, req.Projected12MTB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// UpdatePlanningTargets upserts the cp_planning_targets singleton.
func (h *CapacityPlanningHandler) UpdatePlanningTargets(c *gin.Context) {
	var req struct {
		CostPerEndpointTarget int64 `json:"cost_per_endpoint_target"`
		AnalystHeadroom       int   `json:"analyst_headroom"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		INSERT INTO cp_planning_targets (id, cost_per_endpoint_target, analyst_headroom, updated_at)
		VALUES (1, $1, $2, NOW())
		ON CONFLICT (id) DO UPDATE SET
			cost_per_endpoint_target = EXCLUDED.cost_per_endpoint_target,
			analyst_headroom = EXCLUDED.analyst_headroom,
			updated_at = NOW()`,
		req.CostPerEndpointTarget, req.AnalystHeadroom)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Analysts ──────────────────────────────────────────────────────

type analystReq struct {
	Name                string          `json:"name"`
	Role                string          `json:"role"`
	Skills              json.RawMessage `json:"skills"`
	AlertsHandledPerDay int             `json:"alerts_handled_per_day"`
	HireDate            string          `json:"hire_date"`
}

func (h *CapacityPlanningHandler) CreateAnalyst(c *gin.Context) {
	var req analystReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Skills) == 0 {
		req.Skills = json.RawMessage(`{}`)
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_analysts (name, role, skills, alerts_handled_per_day, hire_date)
		VALUES ($1, $2, $3, $4, COALESCE(NULLIF($5, '')::date, CURRENT_DATE))
		RETURNING id::text`,
		req.Name, req.Role, req.Skills, req.AlertsHandledPerDay, req.HireDate).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateAnalyst(c *gin.Context) {
	id := c.Param("id")
	var req analystReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Skills) == 0 {
		req.Skills = json.RawMessage(`{}`)
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_analysts SET
			name = $1, role = $2, skills = $3,
			alerts_handled_per_day = $4,
			hire_date = COALESCE(NULLIF($5, '')::date, hire_date)
		WHERE id = $6::uuid`,
		req.Name, req.Role, req.Skills, req.AlertsHandledPerDay, req.HireDate, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteAnalyst(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_analysts WHERE id = $1::uuid`, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Tool licenses ─────────────────────────────────────────────────

type licenseReq struct {
	ToolName     string `json:"tool_name"`
	Category     string `json:"category"`
	Purchased    int    `json:"purchased"`
	Used         int    `json:"used"`
	PricePerUnit int64  `json:"price_per_unit"`
	RenewalDate  string `json:"renewal_date"`
	SortOrder    int    `json:"sort_order"`
}

func (h *CapacityPlanningHandler) CreateLicense(c *gin.Context) {
	var req licenseReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_tool_licenses (tool_name, category, purchased, used, price_per_unit, renewal_date, sort_order)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::date, $7)
		RETURNING id::text`,
		req.ToolName, req.Category, req.Purchased, req.Used, req.PricePerUnit, req.RenewalDate, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateLicense(c *gin.Context) {
	id := c.Param("id")
	var req licenseReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_tool_licenses SET
			tool_name = $1, category = $2, purchased = $3, used = $4,
			price_per_unit = $5,
			renewal_date = NULLIF($6, '')::date,
			sort_order = $7
		WHERE id = $8::uuid`,
		req.ToolName, req.Category, req.Purchased, req.Used,
		req.PricePerUnit, req.RenewalDate, req.SortOrder, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteLicense(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_tool_licenses WHERE id = $1::uuid`, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Budget categories ─────────────────────────────────────────────

type budgetReq struct {
	Label       string `json:"label"`
	CurrentYear int64  `json:"current_year"`
	NextYear    int64  `json:"next_year"`
	Year3       int64  `json:"year3"`
	SortOrder   int    `json:"sort_order"`
}

// CreateBudgetCategory uses ON CONFLICT(label) DO UPDATE because label is
// UNIQUE — treating "same label" as an edit prevents duplicate rows.
func (h *CapacityPlanningHandler) CreateBudgetCategory(c *gin.Context) {
	var req budgetReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_budget_categories (label, current_year, next_year, year3, sort_order)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (label) DO UPDATE SET
			current_year = EXCLUDED.current_year,
			next_year = EXCLUDED.next_year,
			year3 = EXCLUDED.year3,
			sort_order = EXCLUDED.sort_order
		RETURNING id::text`,
		req.Label, req.CurrentYear, req.NextYear, req.Year3, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateBudgetCategory(c *gin.Context) {
	label := c.Param("label")
	var req budgetReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_budget_categories SET
			current_year = $1, next_year = $2, year3 = $3, sort_order = $4
		WHERE label = $5`,
		req.CurrentYear, req.NextYear, req.Year3, req.SortOrder, label)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteBudgetCategory(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_budget_categories WHERE label = $1`, c.Param("label"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Planned hires ─────────────────────────────────────────────────

type hireReq struct {
	Role                string `json:"role"`
	PlannedQuarter      string `json:"planned_quarter"`
	EstimatedAnnualCost int64  `json:"estimated_annual_cost"`
	Priority            string `json:"priority"`
	SortOrder           int    `json:"sort_order"`
}

func (h *CapacityPlanningHandler) CreateHire(c *gin.Context) {
	var req hireReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_planned_hires (role, planned_quarter, estimated_annual_cost, priority, sort_order)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text`,
		req.Role, req.PlannedQuarter, req.EstimatedAnnualCost, req.Priority, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateHire(c *gin.Context) {
	id := c.Param("id")
	var req hireReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_planned_hires SET
			role = $1, planned_quarter = $2,
			estimated_annual_cost = $3, priority = $4, sort_order = $5
		WHERE id = $6::uuid`,
		req.Role, req.PlannedQuarter, req.EstimatedAnnualCost, req.Priority, req.SortOrder, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteHire(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_planned_hires WHERE id = $1::uuid`, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Tech debt ─────────────────────────────────────────────────────

type techDebtReq struct {
	Title     string `json:"title"`
	Impact    string `json:"impact"`
	Severity  string `json:"severity"`
	SortOrder int    `json:"sort_order"`
}

func (h *CapacityPlanningHandler) CreateTechDebt(c *gin.Context) {
	var req techDebtReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_tech_debt (title, impact, severity, sort_order)
		VALUES ($1, $2, $3, $4)
		RETURNING id::text`,
		req.Title, req.Impact, req.Severity, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateTechDebt(c *gin.Context) {
	id := c.Param("id")
	var req techDebtReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_tech_debt SET
			title = $1, impact = $2, severity = $3, sort_order = $4
		WHERE id = $5::uuid`,
		req.Title, req.Impact, req.Severity, req.SortOrder, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteTechDebt(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_tech_debt WHERE id = $1::uuid`, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── On-call shifts ────────────────────────────────────────────────

type shiftReq struct {
	Shift     string `json:"shift"`
	StartH    string `json:"start_h"`
	EndH      string `json:"end_h"`
	Mon       string `json:"mon"`
	Tue       string `json:"tue"`
	Wed       string `json:"wed"`
	Thu       string `json:"thu"`
	Fri       string `json:"fri"`
	Sat       string `json:"sat"`
	Sun       string `json:"sun"`
	SortOrder int    `json:"sort_order"`
}

func (h *CapacityPlanningHandler) CreateShift(c *gin.Context) {
	var req shiftReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_oncall_shifts
			(shift, start_h, end_h, mon, tue, wed, thu, fri, sat, sun, sort_order)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id::text`,
		req.Shift, req.StartH, req.EndH, req.Mon, req.Tue, req.Wed, req.Thu,
		req.Fri, req.Sat, req.Sun, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateShift(c *gin.Context) {
	id := c.Param("id")
	var req shiftReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_oncall_shifts SET
			shift = $1, start_h = $2, end_h = $3,
			mon = $4, tue = $5, wed = $6, thu = $7, fri = $8, sat = $9, sun = $10,
			sort_order = $11
		WHERE id = $12::uuid`,
		req.Shift, req.StartH, req.EndH, req.Mon, req.Tue, req.Wed, req.Thu,
		req.Fri, req.Sat, req.Sun, req.SortOrder, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteShift(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_oncall_shifts WHERE id = $1::uuid`, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── ROI inputs ────────────────────────────────────────────────────

type roiReq struct {
	Category              string `json:"category"`
	Label                 string `json:"label"`
	SubLabel              string `json:"sub_label"`
	AnnualInvestment      int64  `json:"annual_investment"`
	BreachPreventionValue int64  `json:"breach_prevention_value"`
	OperationalSavings    int64  `json:"operational_savings"`
	ComplianceValue       int64  `json:"compliance_value"`
	SortOrder             int    `json:"sort_order"`
}

// CreateROIInput uses ON CONFLICT(category) DO UPDATE because category is the
// stable key (edr/siem/soar). This means "add with same category" overwrites,
// which matches the UI intent — the GetROI endpoint synthesizes an "overall"
// row, so callers never create it explicitly.
func (h *CapacityPlanningHandler) CreateROIInput(c *gin.Context) {
	var req roiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// "overall" is reserved — the GET handler synthesizes it from the sum.
	if req.Category == "overall" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category 'overall' is reserved"})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cp_roi_inputs
			(category, label, sub_label, annual_investment,
			 breach_prevention_value, operational_savings, compliance_value, sort_order)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (category) DO UPDATE SET
			label = EXCLUDED.label,
			sub_label = EXCLUDED.sub_label,
			annual_investment = EXCLUDED.annual_investment,
			breach_prevention_value = EXCLUDED.breach_prevention_value,
			operational_savings = EXCLUDED.operational_savings,
			compliance_value = EXCLUDED.compliance_value,
			sort_order = EXCLUDED.sort_order
		RETURNING id::text`,
		req.Category, req.Label, req.SubLabel, req.AnnualInvestment,
		req.BreachPreventionValue, req.OperationalSavings, req.ComplianceValue, req.SortOrder).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (h *CapacityPlanningHandler) UpdateROIInput(c *gin.Context) {
	category := c.Param("category")
	if category == "overall" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category 'overall' is reserved"})
		return
	}
	var req roiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cp_roi_inputs SET
			label = $1, sub_label = $2,
			annual_investment = $3,
			breach_prevention_value = $4,
			operational_savings = $5,
			compliance_value = $6,
			sort_order = $7
		WHERE category = $8`,
		req.Label, req.SubLabel, req.AnnualInvestment,
		req.BreachPreventionValue, req.OperationalSavings, req.ComplianceValue,
		req.SortOrder, category)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CapacityPlanningHandler) DeleteROIInput(c *gin.Context) {
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cp_roi_inputs WHERE category = $1`, c.Param("category"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
