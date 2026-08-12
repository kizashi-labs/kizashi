package handlers_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

func TestCov7_AutoResponse(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutoResponseHandler(store.NewAutoResponseStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/ar", h.Create)
	r.PUT("/ar/:id", h.Update)
	r.PUT("/ar/:id/toggle", h.Toggle)
	r.DELETE("/ar/:id", h.Delete)

	// CreateAutoResponseRuleInput has no json tags → bind by field name (case-insensitive).
	body := gin.H{
		"name":               "cov7-ar",
		"description":        "d",
		"enabled":            true,
		"triggerseveritymin": 5,
		"triggerstatus":      "open",
		"actiontype":         "notify_channel",
		"actionparams":       gin.H{"channel": "soc"},
		"cooldownseconds":    60,
	}
	id := mutID(t, r, "/ar", body)
	body["name"] = "cov7-ar-2"
	if w := jsonReq(r, http.MethodPut, "/ar/"+id, body); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/ar/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/ar/"+id)
}

func TestCov7_CustomAlertRules(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCustomAlertRulesHandler(store.NewCustomAlertRuleStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/car", h.Create)
	r.PUT("/car/:id", h.Update)
	r.PATCH("/car/:id/toggle", h.Toggle)
	r.DELETE("/car/:id", h.Delete)

	// CreateCustomAlertRuleInput has no json tags → bind by field name.
	body := gin.H{
		"name":              "cov7-car",
		"description":       "d",
		"enabled":           true,
		"eventtype":         "process_event",
		"conditions":        []gin.H{{"field": "name", "op": "eq", "value": "x"}},
		"thresholdcount":    1,
		"timewindowseconds": 60,
		"severity":          5,
		"alerttitle":        "cov",
		"alertdescription":  "d",
		"mitretags":         []string{"T1059"},
	}
	id := mutID(t, r, "/car", body)
	body["name"] = "cov7-car-2"
	if w := jsonReq(r, http.MethodPut, "/car/"+id, body); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/car/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/car/"+id)
}

func TestCov7_EndpointGroups(t *testing.T) {
	db := testDB(t)
	h := handlers.NewEndpointGroupsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/eg", h.Create)
	r.PUT("/eg/:id", h.Update)
	r.DELETE("/eg/:id", h.Delete)

	id := createID(t, r, "/eg", gin.H{"name": "cov7-eg", "type": "custom", "description": "d"})
	if w := jsonReq(r, http.MethodPut, "/eg/"+id, gin.H{"name": "cov7-eg-2", "type": "location", "description": "d2"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/eg/"+id)
}

func TestCov7_EscalationRule(t *testing.T) {
	db := testDB(t)
	h := handlers.NewEscalationRuleHandler(store.NewEscalationRuleStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/esc", h.Create)
	r.PUT("/esc/:id", h.Update)
	r.PATCH("/esc/:id/toggle", h.Toggle)
	r.DELETE("/esc/:id", h.Delete)

	id := mutID(t, r, "/esc", gin.H{"name": "cov7-esc", "severity_min": 5, "unresolved_mins": 30, "escalate_to": "admin", "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/esc/"+id, gin.H{"name": "cov7-esc-2", "severity_min": 7, "unresolved_mins": 60, "escalate_to": "admin", "enabled": false}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/esc/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/esc/"+id)
}

func TestCov7_MaintenanceWindow(t *testing.T) {
	db := testDB(t)
	h := handlers.NewMaintenanceWindowHandler(store.NewMaintenanceWindowStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/mw", h.Create)
	r.PUT("/mw/:id", h.Update)
	r.DELETE("/mw/:id", h.Delete)

	start := "2030-01-01T10:00:00Z"
	end := "2030-01-01T12:00:00Z"
	id := mutID(t, r, "/mw", gin.H{"name": "cov7-mw", "start_time": start, "end_time": end, "suppress_alerts": true})
	if w := jsonReq(r, http.MethodPut, "/mw/"+id, gin.H{"name": "cov7-mw-2", "start_time": start, "end_time": end}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/mw/"+id)
}

func TestCov7_NotificationTemplate(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNotificationTemplateHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/nt", h.Create)
	r.PUT("/nt/:id", h.Update)
	r.DELETE("/nt/:id", h.Delete)

	id := mutID(t, r, "/nt", gin.H{"name": "cov7-nt", "channel_type": "email", "body": "hello {{name}}", "variables": []string{"name"}})
	if w := jsonReq(r, http.MethodPut, "/nt/"+id, gin.H{"name": "cov7-nt-2", "body": "hi", "variables": []string{}}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/nt/"+id)
}

func TestCov7_OnCall(t *testing.T) {
	db := testDB(t)
	h := handlers.NewOnCallHandler(db.Pool(), nil)
	r, _ := authRouter(t, db)
	r.POST("/oc", h.CreateIntegration)
	r.PUT("/oc/:id", h.UpdateIntegration)
	r.PUT("/oc/:id/toggle", h.ToggleIntegration)
	r.DELETE("/oc/:id", h.DeleteIntegration)

	id := mutID(t, r, "/oc", gin.H{"name": "cov7-oc", "provider": "pagerduty", "integration_key": "key-" + uuid.NewString()[:8], "severity_threshold": 8})
	if w := jsonReq(r, http.MethodPut, "/oc/"+id, gin.H{"name": "cov7-oc-2", "provider": "opsgenie", "integration_key": "key2", "severity_threshold": 7}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/oc/"+id+"/toggle", gin.H{"enabled": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/oc/"+id)
}

func TestCov7_Patch(t *testing.T) {
	db := testDB(t)
	h := handlers.NewPatchHandler(db.Pool(), nil)
	r, _ := authRouter(t, db)
	r.POST("/pt", h.CreateDeployment)
	r.PUT("/pt/:id", h.UpdateDeployment)
	r.DELETE("/pt/:id", h.DeleteDeployment)

	id := mutID(t, r, "/pt", gin.H{"name": "cov7-patch", "patch_type": "security", "severity": "medium", "target_os": "all", "cve_ids": []string{"CVE-2024-1"}})
	if w := jsonReq(r, http.MethodPut, "/pt/"+id, gin.H{"name": "cov7-patch-2", "severity": "high"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/pt/"+id)
}

func TestCov7_ProcessBlock(t *testing.T) {
	db := testDB(t)
	h := handlers.NewProcessBlockHandler(store.NewProcessBlockRuleStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/pb", h.Create)
	r.PUT("/pb/:id", h.Update)
	r.PATCH("/pb/:id/toggle", h.Toggle)
	r.DELETE("/pb/:id", h.Delete)

	id := mutID(t, r, "/pb", gin.H{"name": "cov7-pb", "process_name": "evil.exe", "rule_type": "deny", "scope": "all", "action": "block", "enabled": true, "severity": "high"})
	if w := jsonReq(r, http.MethodPut, "/pb/"+id, gin.H{"name": "cov7-pb-2", "action": "alert", "severity": "medium"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/pb/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/pb/"+id)
}

func TestCov7_RiskRegister(t *testing.T) {
	db := testDB(t)
	h := handlers.NewRiskRegisterHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rr", h.Create)
	r.PUT("/rr/:id", h.Update)
	r.DELETE("/rr/:id", h.Delete)

	id := mutID(t, r, "/rr", gin.H{"title": "cov7-risk", "description": "d", "category": "operational", "likelihood": 3, "impact": 3, "owner": "sec", "status": "active"})
	if w := jsonReq(r, http.MethodPut, "/rr/"+id, gin.H{"title": "cov7-risk-2", "likelihood": 4, "impact": 2, "status": "mitigated"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/rr/"+id)
}

func TestCov7_SavedHunt(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSavedHuntHandler(store.NewSavedHuntStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/sh", h.Create)
	r.PUT("/sh/:id", h.Update)
	r.DELETE("/sh/:id", h.Delete)

	id := mutID(t, r, "/sh", gin.H{"name": "cov7-sh", "description": "d", "query": "SELECT 1", "query_type": "sql", "tags": []string{"t"}})
	if w := jsonReq(r, http.MethodPut, "/sh/"+id, gin.H{"name": "cov7-sh-2", "query": "SELECT 2", "tags": []string{}}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/sh/"+id)
}

func TestCov7_ThreatFeed(t *testing.T) {
	db := testDB(t)
	h := handlers.NewThreatFeedHandler(store.NewThreatFeedStore(db), store.NewIOCStore(db))
	r, _ := authRouter(t, db)
	r.POST("/tf", h.Create)
	r.PUT("/tf/:id", h.Update)
	r.PATCH("/tf/:id/toggle", h.Toggle)
	r.DELETE("/tf/:id", h.Delete)

	id := mutID(t, r, "/tf", gin.H{"name": "cov7-tf", "url": "http://localhost/feed.txt", "feed_type": "txt", "ioc_type": "ip", "is_active": true, "sync_interval_hours": 24})
	if w := jsonReq(r, http.MethodPut, "/tf/"+id, gin.H{"name": "cov7-tf-2", "url": "http://localhost/feed2.txt", "ioc_type": "domain", "is_active": false}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/tf/"+id+"/toggle", gin.H{"is_active": true}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/tf/"+id)
}

func TestCov7_Webhook(t *testing.T) {
	db := testDB(t)
	h := handlers.NewWebhookHandler(store.NewWebhookStore(db.Pool()), nil)
	r, _ := authRouter(t, db)
	r.POST("/wh", h.Create)
	r.PUT("/wh/:id", h.Update)
	r.PATCH("/wh/:id/toggle", h.Toggle)
	r.DELETE("/wh/:id", h.Delete)

	id := mutID(t, r, "/wh", gin.H{"name": "cov7-wh", "url": "http://localhost/hook", "secret": "s", "events": []string{"alert.critical"}, "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/wh/"+id, gin.H{"name": "cov7-wh-2", "url": "http://localhost/hook2", "enabled": false}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/wh/"+id+"/toggle", gin.H{"enabled": true}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/wh/"+id)
}

func TestCov7_IOC(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIOCHandler(store.NewIOCStore(db))
	r, _ := authRouter(t, db)
	r.POST("/ioc", h.Create)
	r.PUT("/ioc/:id/toggle", h.Toggle)
	r.DELETE("/ioc/:id", h.Delete)

	value := "10.0.0." + uuid.NewString()[:2]
	if w := jsonReq(r, http.MethodPost, "/ioc", gin.H{"type": "ip", "value": value, "description": "cov7", "severity": 7}); w.Code >= 400 {
		t.Fatalf("create ioc = %d: %s", w.Code, w.Body.String())
	}
	var id string
	if err := db.Pool().QueryRow(contextBG(),
		`SELECT id::text FROM ioc_entries WHERE value=$1 ORDER BY created_at DESC LIMIT 1`, value).Scan(&id); err != nil {
		t.Fatalf("lookup ioc: %v", err)
	}
	if w := jsonReq(r, http.MethodPut, "/ioc/"+id+"/toggle", gin.H{"is_active": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/ioc/"+id)
}

func TestCov7_Hunt(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHuntHandler(store.NewHuntStore(db))
	r, _ := authRouter(t, db)
	r.POST("/ht", h.CreateSavedHunt)
	r.DELETE("/ht/:id", h.DeleteSavedHunt)

	id := mutID(t, r, "/ht", gin.H{"name": "cov7-hunt", "description": "d", "params": gin.H{"q": "x"}})
	delOK(t, r, "/ht/"+id)
}

func TestCov7_SOARWorkflow(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSOARWorkflowHandler(db.Pool(), nil)
	r, _ := authRouter(t, db)
	r.POST("/sw", h.CreateWorkflow)
	r.PUT("/sw/:id", h.UpdateWorkflow)
	r.PUT("/sw/:id/toggle", h.ToggleWorkflow)
	r.DELETE("/sw/:id", h.DeleteWorkflow)

	id := mutID(t, r, "/sw", gin.H{"name": "cov7-soar", "description": "d", "trigger_type": "alert", "trigger_conditions": gin.H{"severity": 8}, "actions": []gin.H{{"type": "notify"}}, "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/sw/"+id, gin.H{"name": "cov7-soar-2", "trigger_type": "manual"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/sw/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/sw/"+id)
}

func TestCov7_Campaigns(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCampaignsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/cmp", h.Create)
	r.PUT("/cmp/:id", h.Update)
	r.DELETE("/cmp/:id", h.Delete)

	id := mutID(t, r, "/cmp", gin.H{"name": "cov7-cmp", "description": "d", "threat_actor": "APT-cov", "status": "active", "severity": "medium", "techniques": []string{"T1059"}})
	if w := jsonReq(r, http.MethodPut, "/cmp/"+id, gin.H{"name": "cov7-cmp-2", "status": "active"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/cmp/"+id)
}
