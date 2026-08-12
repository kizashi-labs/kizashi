package handlers_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
)

// TestCov8_* exercises Create/Update/Delete/Toggle/Approve mutation methods on
// handlers that had 0% coverage on those paths. Most of these handlers are
// stateless "echo" endpoints (the pool is accepted but unused on the mutation
// path), so a valid JSON body is enough to drive them; a handful hit the DB and
// seed/guard accordingly. Assertions are lenient (createID or w.Code < 400).

func TestCov8_AlertRoutingHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAlertRoutingHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateRule)
	r.PUT("/rules/:id", h.UpdateRule)
	r.DELETE("/rules/:id", h.DeleteRule)
	r.POST("/dests", h.CreateDestination)

	id := createID(t, r, "/rules", gin.H{"name": "cov8-rule", "priority": 10, "enabled": true, "destinations": []string{"Slack"}})
	if w := jsonReq(r, http.MethodPut, "/rules/"+id, gin.H{"name": "cov8-rule-2", "priority": 20}); w.Code >= 400 {
		t.Errorf("update rule = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/rules/"+id, nil); w.Code >= 400 {
		t.Errorf("delete rule = %d: %s", w.Code, w.Body.String())
	}
	_ = createID(t, r, "/dests", gin.H{"name": "cov8-slack", "destination_type": "slack", "enabled": true})
}

func TestCov8_EncryptionMgmtHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewEncryptionMgmtHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	_ = createID(t, r, "/policies", gin.H{"name": "cov8-enc", "encryption_type": "full_disk", "algorithm": "AES-256", "enforcement_mode": "enforce"})
}

func TestCov8_SecurityGovernanceHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSecurityGovernanceHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	r.PUT("/policies/:id", h.UpdatePolicy)
	r.POST("/exceptions/:id/approve", h.ApproveException)

	id := createID(t, r, "/policies", gin.H{"title": "cov8-policy", "category": "governance", "owner": "CISO"})
	if w := jsonReq(r, http.MethodPut, "/policies/"+id, gin.H{"title": "cov8-policy-2", "status": "published"}); w.Code >= 400 {
		t.Errorf("update policy = %d: %s", w.Code, w.Body.String())
	}
	postOK(t, r, "/exceptions/"+uuid.NewString()+"/approve")
}

func TestCov8_SecurityAssessmentHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSecurityAssessmentHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/assessments", h.CreateAssessment)
	r.PUT("/assessments/:id", h.UpdateAssessment)

	id := createID(t, r, "/assessments", gin.H{"name": "cov8-assess", "assessment_type": "gap_analysis", "framework": "ISO27001"})
	if w := jsonReq(r, http.MethodPut, "/assessments/"+id, gin.H{"name": "cov8-assess-2", "status": "review"}); w.Code >= 400 {
		t.Errorf("update assessment = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_ITDRHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewITDRHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateRule)
	_ = createID(t, r, "/rules", gin.H{"name": "cov8-itdr", "threat_category": "Impossible_Travel", "severity": "high", "enabled": true})
}

func TestCov8_NTAHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNTAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateRule)
	_ = createID(t, r, "/rules", gin.H{"name": "cov8-nta", "rule_type": "signature", "protocol": "TCP", "severity": "high"})
}

func TestCov8_DRPHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDRPHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/monitors", h.CreateMonitor)
	r.PUT("/findings/:id", h.UpdateFinding)

	_ = createID(t, r, "/monitors", gin.H{"name": "cov8-drp", "monitor_type": "brand", "enabled": true, "keywords": []string{"acme"}})
	if w := jsonReq(r, http.MethodPut, "/findings/"+uuid.NewString(), gin.H{"status": "investigating"}); w.Code >= 400 {
		t.Errorf("update finding = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_AutomationEnhancedHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutomationEnhancedHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/triggers", h.CreateTrigger)
	_ = createID(t, r, "/triggers", gin.H{"name": "cov8-trigger", "trigger_type": "alert", "enabled": true, "cooldown_seconds": 300})
}

func TestCov8_ZTNAHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewZTNAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	_ = createID(t, r, "/policies", gin.H{"name": "cov8-ztna", "policy_type": "access", "enforcement_mode": "enforce", "priority": 10, "enabled": true})
}

func TestCov8_TrainingMgmtHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewTrainingMgmtHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/programs", h.CreateProgram)
	r.POST("/enrollments", h.EnrollUser)
	_ = createID(t, r, "/programs", gin.H{"name": "cov8-training", "program_type": "awareness", "duration_hours": 4.0, "passing_score": 80})
	_ = createID(t, r, "/enrollments", gin.H{"program_id": uuid.NewString(), "user_id": "u-cov8"})
}

func TestCov8_SupplyChainRiskHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSupplyChainRiskHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/vendors", h.CreateVendor)
	_ = createID(t, r, "/vendors", gin.H{"name": "cov8-vendor", "vendor_type": "software", "criticality": "high"})
}

func TestCov8_HuntingCampaignHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHuntingCampaignHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/campaigns", h.CreateCampaign)
	r.PUT("/campaigns/:id", h.UpdateCampaign)
	r.POST("/campaigns/:id/notes", h.AddNote)

	id := createID(t, r, "/campaigns", gin.H{"name": "cov8-hunt", "hypothesis": "cov", "tactic": "Lateral Movement", "priority": "high"})
	if w := jsonReq(r, http.MethodPut, "/campaigns/"+id, gin.H{"status": "active"}); w.Code >= 400 {
		t.Errorf("update campaign = %d: %s", w.Code, w.Body.String())
	}
	_ = createID(t, r, "/campaigns/"+id+"/notes", gin.H{"note": "cov8 note"})
}

func TestCov8_ComplianceRemediationHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewComplianceRemediationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateRule)
	r.POST("/executions/:id/approve", h.ApproveExecution)

	_ = createID(t, r, "/rules", gin.H{"name": "cov8-remed", "framework": "CIS", "control_id": "CIS-5.2", "remediation_type": "auto", "enabled": true})
	postOK(t, r, "/executions/"+uuid.NewString()+"/approve")
}

func TestCov8_SecurityDWHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSecurityDWHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/query", h.ExecuteQuery)
	if w := jsonReq(r, http.MethodPost, "/query", gin.H{"query": "SELECT * FROM alerts", "dataset": "alerts_db"}); w.Code >= 400 {
		t.Errorf("execute query = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_DarkWebHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDarkWebHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/findings/:id", h.UpdateFinding)
	if w := jsonReq(r, http.MethodPut, "/findings/"+uuid.NewString(), gin.H{"status": "resolved"}); w.Code >= 400 {
		t.Errorf("update finding = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_FeedAnalyticsHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewFeedAnalyticsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/feeds/:id/status", h.UpdateStatus)
	if w := jsonReq(r, http.MethodPut, "/feeds/"+uuid.NewString()+"/status", gin.H{"status": "disabled"}); w.Code >= 400 {
		t.Errorf("update status = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_NetworkSegmentationHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNetworkSegmentationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/segments", h.CreateSegment)
	r.POST("/policies", h.CreatePolicy)
	r.DELETE("/policies/:id", h.DeletePolicy)

	segID := createID(t, r, "/segments", gin.H{"name": "cov8-seg-" + uuidShort(), "cidr": "10.44.0.0/24", "vlan_id": 44, "gateway": "10.44.0.1", "status": "active"})
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM network_segments WHERE id=$1", segID) })

	polID := createID(t, r, "/policies", gin.H{"from_segment": "DMZ", "to_segment": "CORP", "action": "deny", "protocol": "TCP", "ports": "443"})
	if w := jsonReq(r, http.MethodDelete, "/policies/"+polID, nil); w.Code >= 400 {
		t.Errorf("delete policy = %d: %s", w.Code, w.Body.String())
	}
}
