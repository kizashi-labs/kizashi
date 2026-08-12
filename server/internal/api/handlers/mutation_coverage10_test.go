package handlers_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
)

// put issues a PUT and fails on >= 400.
func put400(t *testing.T, r http.Handler, p string, body any) {
	t.Helper()
	if w := jsonReq(r, http.MethodPut, p, body); w.Code >= 400 {
		t.Errorf("PUT %s = %d: %s", p, w.Code, w.Body.String())
	}
}

// TestCov10_CapacityPlanning exercises the full mutation surface of the
// capacity-planning admin page (all pool-backed CRUD + singleton upserts).
func TestCov10_CapacityPlanning(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCapacityPlanningHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/storage", h.UpdateStorage)
	r.PUT("/targets", h.UpdatePlanningTargets)
	r.POST("/analysts", h.CreateAnalyst)
	r.PUT("/analysts/:id", h.UpdateAnalyst)
	r.DELETE("/analysts/:id", h.DeleteAnalyst)
	r.POST("/licenses", h.CreateLicense)
	r.PUT("/licenses/:id", h.UpdateLicense)
	r.DELETE("/licenses/:id", h.DeleteLicense)
	r.POST("/budgets", h.CreateBudgetCategory)
	r.PUT("/budgets/:label", h.UpdateBudgetCategory)
	r.DELETE("/budgets/:label", h.DeleteBudgetCategory)
	r.POST("/hires", h.CreateHire)
	r.PUT("/hires/:id", h.UpdateHire)
	r.DELETE("/hires/:id", h.DeleteHire)
	r.POST("/techdebt", h.CreateTechDebt)
	r.PUT("/techdebt/:id", h.UpdateTechDebt)
	r.DELETE("/techdebt/:id", h.DeleteTechDebt)
	r.POST("/shifts", h.CreateShift)
	r.PUT("/shifts/:id", h.UpdateShift)
	r.DELETE("/shifts/:id", h.DeleteShift)
	r.POST("/roi", h.CreateROIInput)
	r.PUT("/roi/:category", h.UpdateROIInput)
	r.DELETE("/roi/:category", h.DeleteROIInput)

	put400(t, r, "/storage", gin.H{"used_tb": 10.5, "total_tb": 100, "projected_6m_tb": 20, "projected_12m_tb": 30})
	put400(t, r, "/targets", gin.H{"cost_per_endpoint_target": 500, "analyst_headroom": 3})

	aID := mutID(t, r, "/analysts", gin.H{"name": "cov-analyst", "role": "tier1", "alerts_handled_per_day": 40})
	put400(t, r, "/analysts/"+aID, gin.H{"name": "cov-analyst-2", "role": "tier2", "alerts_handled_per_day": 55})
	delOK(t, r, "/analysts/"+aID)

	lID := mutID(t, r, "/licenses", gin.H{"tool_name": "cov-tool", "category": "edr", "purchased": 100, "used": 40, "price_per_unit": 12, "sort_order": 1})
	put400(t, r, "/licenses/"+lID, gin.H{"tool_name": "cov-tool", "category": "siem", "purchased": 120, "used": 45, "price_per_unit": 13, "sort_order": 2})
	delOK(t, r, "/licenses/"+lID)

	label := "cov-budget-" + uuidShort()
	_ = mutID(t, r, "/budgets", gin.H{"label": label, "current_year": 1000, "next_year": 1100, "year3": 1200, "sort_order": 1})
	put400(t, r, "/budgets/"+label, gin.H{"current_year": 2000, "next_year": 2100, "year3": 2200, "sort_order": 2})
	delOK(t, r, "/budgets/"+label)

	hID := mutID(t, r, "/hires", gin.H{"role": "analyst", "planned_quarter": "Q3", "estimated_annual_cost": 90000, "priority": "high", "sort_order": 1})
	put400(t, r, "/hires/"+hID, gin.H{"role": "senior analyst", "planned_quarter": "Q4", "estimated_annual_cost": 110000, "priority": "medium", "sort_order": 2})
	delOK(t, r, "/hires/"+hID)

	tID := mutID(t, r, "/techdebt", gin.H{"title": "cov-debt", "impact": "medium", "severity": "high", "sort_order": 1})
	put400(t, r, "/techdebt/"+tID, gin.H{"title": "cov-debt-2", "impact": "high", "severity": "medium", "sort_order": 2})
	delOK(t, r, "/techdebt/"+tID)

	sID := mutID(t, r, "/shifts", gin.H{"shift": "cov-day", "start_h": "09", "end_h": "17", "mon": "a", "tue": "a", "wed": "a", "thu": "a", "fri": "a", "sat": "", "sun": "", "sort_order": 1})
	put400(t, r, "/shifts/"+sID, gin.H{"shift": "cov-night", "start_h": "17", "end_h": "01", "mon": "b", "tue": "b", "wed": "b", "thu": "b", "fri": "b", "sat": "b", "sun": "", "sort_order": 2})
	delOK(t, r, "/shifts/"+sID)

	cat := "cov-roi-" + uuidShort()
	_ = mutID(t, r, "/roi", gin.H{"category": cat, "label": "Cov ROI", "sub_label": "x", "annual_investment": 100000, "breach_prevention_value": 500000, "operational_savings": 20000, "compliance_value": 10000, "sort_order": 1})
	put400(t, r, "/roi/"+cat, gin.H{"label": "Cov ROI 2", "sub_label": "y", "annual_investment": 120000, "breach_prevention_value": 600000, "operational_savings": 25000, "compliance_value": 15000, "sort_order": 2})
	delOK(t, r, "/roi/"+cat)
}

// TestCov10_OAuth2 covers OAuth2 client create/update/delete.
func TestCov10_OAuth2(t *testing.T) {
	db := testDB(t)
	h := handlers.NewOAuth2Handler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/clients", h.CreateClient)
	r.PUT("/clients/:id", h.UpdateClient)
	r.DELETE("/clients/:id", h.DeleteClient)

	id := createID(t, r, "/clients", gin.H{"name": "cov-oauth", "description": "d", "redirect_uris": []string{"https://x/cb"}, "allowed_scopes": []string{"read"}, "grant_types": []string{"authorization_code"}, "is_confidential": true})
	put400(t, r, "/clients/"+id, gin.H{"name": "cov-oauth-2", "description": "updated"})
	delOK(t, r, "/clients/"+id)
}

// TestCov10_IncidentPattern covers incident pattern CRUD + toggle + match status.
func TestCov10_IncidentPattern(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIncidentPatternHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/patterns", h.CreatePattern)
	r.PUT("/patterns/:id", h.UpdatePattern)
	r.POST("/patterns/:id/toggle", h.TogglePattern)
	r.DELETE("/patterns/:id", h.DeletePattern)
	r.PATCH("/matches/:id/status", h.UpdateMatchStatus)

	id := createID(t, r, "/patterns", gin.H{"name": "cov-pattern", "pattern_type": "sequence", "severity": "medium"})
	put400(t, r, "/patterns/"+id, gin.H{"name": "cov-pattern-2", "pattern_type": "sequence", "severity": "high", "confidence_threshold": 0.8, "is_active": true})
	postOK(t, r, "/patterns/"+id+"/toggle")
	// UpdateMatchStatus tolerates a missing row (no RowsAffected check).
	if w := jsonReq(r, http.MethodPatch, "/matches/"+uuid.NewString()+"/status", gin.H{"status": "reviewed"}); w.Code >= 400 {
		t.Errorf("update match status = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/patterns/"+id)
}

// TestCov10_LogAnalysis covers parse rule CRUD + job create.
func TestCov10_LogAnalysis(t *testing.T) {
	db := testDB(t)
	h := handlers.NewLogAnalysisHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateParseRule)
	r.PUT("/rules/:id", h.UpdateParseRule)
	r.DELETE("/rules/:id", h.DeleteParseRule)
	r.POST("/jobs", h.CreateJob)

	id := createID(t, r, "/rules", gin.H{"name": "cov-rule", "log_source": "syslog", "pattern": "(?P<ip>\\d+)", "priority": 50})
	put400(t, r, "/rules/"+id, gin.H{"name": "cov-rule-2", "priority": 60})
	delOK(t, r, "/rules/"+id)

	// CreateJob spawns a background counter goroutine but returns immediately.
	if w := jsonReq(r, http.MethodPost, "/jobs", gin.H{"name": "cov-job", "query": "error", "time_range": "1h"}); w.Code >= 400 {
		t.Errorf("create job = %d: %s", w.Code, w.Body.String())
	}
}

// TestCov10_MultiTenant covers tenant create/update/quota/delete.
func TestCov10_MultiTenant(t *testing.T) {
	db := testDB(t)
	h := handlers.NewMultiTenantHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/tenants", h.CreateTenant)
	r.PUT("/tenants/:id", h.UpdateTenant)
	r.PUT("/tenants/:id/quota", h.UpdateQuota)
	r.DELETE("/tenants/:id", h.DeleteTenant)

	slug := "cov-" + uuidShort()
	id := createID(t, r, "/tenants", gin.H{"name": "Cov Tenant", "slug": slug, "plan": "standard", "max_agents": 50})
	put400(t, r, "/tenants/"+id, gin.H{"name": "Cov Tenant 2", "max_agents": 75})
	put400(t, r, "/tenants/"+id+"/quota", gin.H{"max_agents": 80, "max_users": 40, "plan": "pro"})
	delOK(t, r, "/tenants/"+id)
}

// TestCov10_Chaos covers chaos approval create/update.
func TestCov10_Chaos(t *testing.T) {
	db := testDB(t)
	h := handlers.NewChaosHandler(db.Pool())
	uid := seedTestUser(t, db)
	tenantID := uuid.NewString()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("tenant_id", tenantID)
		c.Next()
	})
	r.POST("/approvals", h.CreateApproval)
	r.PUT("/approvals/:id", h.UpdateApproval)

	id := mutID(t, r, "/approvals", gin.H{"experiment_id": uuid.NewString(), "justification": "cov test", "approvers": []string{"alice"}})
	put400(t, r, "/approvals/"+id, gin.H{"status": "approved"})
}

// TestCov10_CloudIdentity covers cloud identity provider CRUD.
func TestCov10_CloudIdentity(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudIdentityHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/providers", h.CreateProvider)
	r.PUT("/providers/:id", h.UpdateProvider)
	r.DELETE("/providers/:id", h.DeleteProvider)

	id := createID(t, r, "/providers", gin.H{"name": "cov-idp", "provider_type": "okta", "config": gin.H{"domain": "x"}})
	put400(t, r, "/providers/"+id, gin.H{"name": "cov-idp-2", "is_active": false})
	delOK(t, r, "/providers/"+id)
}

// TestCov10_Honeynet covers honeynet node CRUD.
func TestCov10_Honeynet(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHoneynetHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/nodes", h.CreateNode)
	r.PUT("/nodes/:id", h.UpdateNode)
	r.DELETE("/nodes/:id", h.DeleteNode)

	id := createID(t, r, "/nodes", gin.H{"name": "cov-node", "node_type": "honeypot", "network_segment": "dmz"})
	put400(t, r, "/nodes/"+id, gin.H{"name": "cov-node-2", "node_type": "honeypot", "is_active": true})
	delOK(t, r, "/nodes/"+id)
}

// TestCov10_Honeypot covers honeypot CRUD.
func TestCov10_Honeypot(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHoneypotHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/hp", h.Create)
	r.PUT("/hp/:id", h.Update)
	r.DELETE("/hp/:id", h.Delete)

	id := createID(t, r, "/hp", gin.H{"name": "cov-hp", "honeypot_type": "http", "listen_address": "0.0.0.0", "listen_port": 8080})
	put400(t, r, "/hp/"+id, gin.H{"name": "cov-hp-2", "description": "d", "honeypot_type": "http", "listen_address": "0.0.0.0", "listen_port": 9090, "enabled": true, "alert_on_access": true})
	delOK(t, r, "/hp/"+id)
}

// TestCov10_ContextEnrichment covers enrichment source create/update.
func TestCov10_ContextEnrichment(t *testing.T) {
	db := testDB(t)
	h := handlers.NewContextEnrichmentHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/sources", h.CreateSource)
	r.PUT("/sources/:id", h.UpdateSource)

	id := createID(t, r, "/sources", gin.H{"name": "cov-src", "source_type": "virustotal", "daily_limit": 500, "avg_latency_ms": 150})
	put400(t, r, "/sources/"+id, gin.H{"name": "cov-src-2", "daily_limit": 1000})
}

// TestCov10_AutonomousPolicy covers autonomous response policy CRUD + toggle.
func TestCov10_AutonomousPolicy(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutonomousPolicyHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	r.PUT("/policies/:id", h.UpdatePolicy)
	r.POST("/policies/:id/toggle", h.TogglePolicy)
	r.DELETE("/policies/:id", h.DeletePolicy)

	id := createID(t, r, "/policies", gin.H{"name": "cov-arp", "requires_approval": true, "approval_timeout_s": 300, "max_scope": "single_host"})
	put400(t, r, "/policies/"+id, gin.H{"name": "cov-arp-2", "max_scope": "network"})
	postOK(t, r, "/policies/"+id+"/toggle")
	delOK(t, r, "/policies/"+id)
}

// TestCov10_MetricsReport covers report generation + delete.
func TestCov10_MetricsReport(t *testing.T) {
	db := testDB(t)
	h := handlers.NewMetricsReportHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/reports", h.GenerateReport)
	r.DELETE("/reports/:id", h.DeleteReport)

	// GenerateReport returns 202 Accepted with an id (mutID only accepts 200/201).
	w := jsonReq(r, http.MethodPost, "/reports", gin.H{"name": "cov-report", "report_type": "executive_summary", "output_format": "pdf"})
	if w.Code >= 400 {
		t.Fatalf("generate report = %d: %s", w.Code, w.Body.String())
	}
	var gr struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &gr)
	if gr.ID != "" {
		delOK(t, r, "/reports/"+gr.ID)
	}
}

// TestCov10_CorrelationEngine covers correlation rule create/update/delete.
func TestCov10_CorrelationEngine(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCorrelationEngineHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.Create)
	r.PUT("/rules/:id", h.Update)
	r.DELETE("/rules/:id", h.Delete)

	id := createID(t, r, "/rules", gin.H{
		"name": "cov-corr", "trigger_event_type": "process_start", "follow_event_type": "network_connect",
		"alert_title": "Cov Alert", "alert_severity": 7, "time_window_seconds": 300, "cooldown_seconds": 60,
	})
	put400(t, r, "/rules/"+id, gin.H{
		"name": "cov-corr-2", "trigger_event_type": "process_start", "follow_event_type": "file_write",
		"alert_title": "Cov Alert 2", "alert_severity": 8, "time_window_seconds": 600, "cooldown_seconds": 120,
	})
	delOK(t, r, "/rules/"+id)
}
