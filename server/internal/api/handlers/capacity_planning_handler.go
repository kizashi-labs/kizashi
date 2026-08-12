package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityPlanningHandler serves read-only data for the /admin/capacity-planning page.
type CapacityPlanningHandler struct {
	pool *pgxpool.Pool
}

func NewCapacityPlanningHandler(pool *pgxpool.Pool) *CapacityPlanningHandler {
	return &CapacityPlanningHandler{pool: pool}
}

// GetOverview returns aggregate KPIs. `alerts_per_day` is the 7-day rolling
// average derived from the actual alerts table so the value tracks reality
// without a separate cron. Planning targets (endpoint unit cost, analyst
// headroom) come from cp_planning_targets so they are editable without a
// code change.
func (h *CapacityPlanningHandler) GetOverview(c *gin.Context) {
	ctx := c.Request.Context()

	var alertCount int
	_ = h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE created_at >= NOW() - INTERVAL '7 days'`).Scan(&alertCount)

	alertsPerDay := alertCount / 7
	if alertCount > 0 && alertsPerDay == 0 {
		alertsPerDay = 1
	}

	var costTarget int64 = 500000
	var headroom int = 2
	_ = h.pool.QueryRow(ctx, `
		SELECT cost_per_endpoint_target, analyst_headroom
		FROM cp_planning_targets WHERE id = 1`).Scan(&costTarget, &headroom)

	c.JSON(http.StatusOK, gin.H{
		"alerts_per_day":           alertsPerDay,
		"cost_per_endpoint_target": costTarget,
		"analyst_headroom":         headroom,
	})
}

// GetROI computes ROI per category from investment vs. benefit inputs and
// returns them with a pre-selected color class for the card. An "overall"
// row is synthesized by aggregating the other rows so the number is
// mathematically consistent with the parts.
func (h *CapacityPlanningHandler) GetROI(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT category, label, sub_label,
		       annual_investment, breach_prevention_value,
		       operational_savings, compliance_value
		FROM cp_roi_inputs ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type ROIItem struct {
		Category        string `json:"category"`
		Label           string `json:"label"`
		SubLabel        string `json:"sub_label"`
		Investment      int64  `json:"annual_investment"`
		BreachValue     int64  `json:"breach_prevention_value"`
		OperationalSave int64  `json:"operational_savings"`
		ComplianceValue int64  `json:"compliance_value"`
		Benefit         int64  `json:"annual_benefit"`
		ROIPct          int    `json:"roi_pct"`
		Color           string `json:"color"`
	}

	pickColor := func(pct int) string {
		switch {
		case pct >= 200:
			return "green"
		case pct >= 100:
			return "yellow"
		default:
			return "red"
		}
	}

	computeROI := func(benefit, investment int64) int {
		if investment <= 0 {
			return 0
		}
		return int(benefit * 100 / investment)
	}

	out := []ROIItem{}
	var sumInv, sumBen, sumBP, sumOps, sumComp int64
	for rows.Next() {
		var it ROIItem
		if rows.Scan(&it.Category, &it.Label, &it.SubLabel,
			&it.Investment, &it.BreachValue, &it.OperationalSave, &it.ComplianceValue) != nil {
			continue
		}
		it.Benefit = it.BreachValue + it.OperationalSave + it.ComplianceValue
		it.ROIPct = computeROI(it.Benefit, it.Investment)
		it.Color = pickColor(it.ROIPct)
		sumInv += it.Investment
		sumBen += it.Benefit
		sumBP += it.BreachValue
		sumOps += it.OperationalSave
		sumComp += it.ComplianceValue
		out = append(out, it)
	}

	overallPct := computeROI(sumBen, sumInv)
	out = append(out, ROIItem{
		Category:        "overall",
		Label:           "総合セキュリティROI",
		SubLabel:        "推定年間効果",
		Investment:      sumInv,
		BreachValue:     sumBP,
		OperationalSave: sumOps,
		ComplianceValue: sumComp,
		Benefit:         sumBen,
		ROIPct:          overallPct,
		Color:           pickColor(overallPct),
	})

	c.JSON(http.StatusOK, out)
}

// GetWorkforce returns the analyst roster.
func (h *CapacityPlanningHandler) GetWorkforce(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, name, role, skills, alerts_handled_per_day,
		       TO_CHAR(hire_date, 'YYYY-MM-DD')
		FROM cp_analysts ORDER BY hire_date ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Analyst struct {
		ID                  string          `json:"id"`
		Name                string          `json:"name"`
		Role                string          `json:"role"`
		Skills              json.RawMessage `json:"skills"`
		AlertsHandledPerDay int             `json:"alerts_handled_per_day"`
		HireDate            string          `json:"hire_date"`
	}
	out := []Analyst{}
	for rows.Next() {
		var a Analyst
		if rows.Scan(&a.ID, &a.Name, &a.Role, &a.Skills, &a.AlertsHandledPerDay, &a.HireDate) == nil {
			out = append(out, a)
		}
	}
	c.JSON(http.StatusOK, out)
}

// GetResources returns tool/license inventory. The EDR row's `used` column is
// overridden with the live agent count so the license gauge stays accurate.
func (h *CapacityPlanningHandler) GetResources(c *gin.Context) {
	ctx := c.Request.Context()

	var liveAgentCount int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&liveAgentCount)

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, tool_name, category, purchased, used, price_per_unit,
		       COALESCE(TO_CHAR(renewal_date, 'YYYY-MM-DD'), '')
		FROM cp_tool_licenses ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type License struct {
		ID           string `json:"id"`
		ToolName     string `json:"tool_name"`
		Category     string `json:"category"`
		Purchased    int    `json:"purchased"`
		Used         int    `json:"used"`
		PricePerUnit int64  `json:"price_per_unit"`
		RenewalDate  string `json:"renewal_date"`
	}
	out := []License{}
	for rows.Next() {
		var l License
		if rows.Scan(&l.ID, &l.ToolName, &l.Category, &l.Purchased, &l.Used,
			&l.PricePerUnit, &l.RenewalDate) == nil {
			if l.Category == "EDR" && liveAgentCount > 0 {
				l.Used = liveAgentCount
			}
			out = append(out, l)
		}
	}
	c.JSON(http.StatusOK, out)
}

// GetStorage returns the singleton storage capacity row.
func (h *CapacityPlanningHandler) GetStorage(c *gin.Context) {
	ctx := c.Request.Context()

	var used, total, p6, p12 float64
	err := h.pool.QueryRow(ctx, `
		SELECT used_tb, total_tb, projected_6m_tb, projected_12m_tb
		FROM cp_storage_metrics WHERE id = 1`).Scan(&used, &total, &p6, &p12)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"used_tb": 0, "total_tb": 1, "projected_6m_tb": 0, "projected_12m_tb": 0,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"used_tb":          used,
		"total_tb":         total,
		"projected_6m_tb":  p6,
		"projected_12m_tb": p12,
	})
}

// GetBudget returns budget categories for current/next/year3.
func (h *CapacityPlanningHandler) GetBudget(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT label, current_year, next_year, year3
		FROM cp_budget_categories ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Category struct {
		Label       string `json:"label"`
		CurrentYear int64  `json:"current_year"`
		NextYear    int64  `json:"next_year"`
		Year3       int64  `json:"year3"`
	}
	out := []Category{}
	for rows.Next() {
		var b Category
		if rows.Scan(&b.Label, &b.CurrentYear, &b.NextYear, &b.Year3) == nil {
			out = append(out, b)
		}
	}
	c.JSON(http.StatusOK, out)
}

// GetPlannedHires returns the hiring roadmap. `id` is exposed so the admin
// editor can target individual rows with PUT/DELETE.
func (h *CapacityPlanningHandler) GetPlannedHires(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, role, planned_quarter, estimated_annual_cost, priority
		FROM cp_planned_hires ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Hire struct {
		ID                  string `json:"id"`
		Role                string `json:"role"`
		PlannedQuarter      string `json:"planned_quarter"`
		EstimatedAnnualCost int64  `json:"estimated_annual_cost"`
		Priority            string `json:"priority"`
	}
	out := []Hire{}
	for rows.Next() {
		var h Hire
		if rows.Scan(&h.ID, &h.Role, &h.PlannedQuarter, &h.EstimatedAnnualCost, &h.Priority) == nil {
			out = append(out, h)
		}
	}
	c.JSON(http.StatusOK, out)
}

// GetTechDebt returns technical debt items.
func (h *CapacityPlanningHandler) GetTechDebt(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, title, impact, severity
		FROM cp_tech_debt ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Debt struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Impact   string `json:"impact"`
		Severity string `json:"severity"`
	}
	out := []Debt{}
	for rows.Next() {
		var d Debt
		if rows.Scan(&d.ID, &d.Title, &d.Impact, &d.Severity) == nil {
			out = append(out, d)
		}
	}
	c.JSON(http.StatusOK, out)
}

// GetOncallShifts returns the weekly on-call matrix.
func (h *CapacityPlanningHandler) GetOncallShifts(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, shift, start_h, end_h, mon, tue, wed, thu, fri, sat, sun
		FROM cp_oncall_shifts ORDER BY sort_order ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Shift struct {
		ID      string `json:"id"`
		Analyst string `json:"analyst"`
		Shift   string `json:"shift"`
		Start   string `json:"start"`
		End     string `json:"end"`
		Mon     string `json:"mon"`
		Tue     string `json:"tue"`
		Wed     string `json:"wed"`
		Thu     string `json:"thu"`
		Fri     string `json:"fri"`
		Sat     string `json:"sat"`
		Sun     string `json:"sun"`
	}
	out := []Shift{}
	for rows.Next() {
		var s Shift
		if rows.Scan(&s.ID, &s.Shift, &s.Start, &s.End,
			&s.Mon, &s.Tue, &s.Wed, &s.Thu, &s.Fri, &s.Sat, &s.Sun) == nil {
			out = append(out, s)
		}
	}
	c.JSON(http.StatusOK, out)
}
