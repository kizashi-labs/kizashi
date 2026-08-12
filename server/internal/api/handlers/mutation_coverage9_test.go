package handlers_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// TestCov9_* exercises 0%-coverage mutation methods on handlers not touched by
// the existing mutation_coverage*/get_coverage* batches. Assertions are lenient:
// createID (201) or w.Code < 400.

func TestCov9_AssetCriticalityHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAssetCriticalityHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/endpoints/:id/criticality", h.SetManualScore)
	r.POST("/endpoints/criticality/bulk", h.BulkScore)

	agentID := uuid.NewString()
	if w := jsonReq(r, http.MethodPut, "/endpoints/"+agentID+"/criticality", gin.H{"score": 72, "reason": "cov9"}); w.Code >= 400 {
		t.Errorf("SetManualScore = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPost, "/endpoints/criticality/bulk", nil); w.Code >= 400 {
		t.Errorf("BulkScore = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_AutoRemediationHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutoRemediationHandler(db.Pool(), nil)
	r, _ := authRouter(t, db)
	r.POST("/agents/:id/remediate", h.ExecuteAction)
	r.POST("/remediate/bulk", h.BulkRemediate)

	agentID := uuid.NewString()
	if w := jsonReq(r, http.MethodPost, "/agents/"+agentID+"/remediate",
		gin.H{"action_type": "kill_process", "target": "1234", "reason": "cov9"}); w.Code >= 400 {
		t.Errorf("ExecuteAction = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPost, "/remediate/bulk",
		gin.H{"agent_ids": []string{uuid.NewString()}, "action_type": "block_ip", "target": "1.2.3.4"}); w.Code >= 400 {
		t.Errorf("BulkRemediate = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_AlertActionHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAlertActionHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/alerts/:id/status", h.UpdateStatus)

	var alertID string
	if err := db.Pool().QueryRow(contextBG(),
		`INSERT INTO alerts (severity, status, title) VALUES (5, 'open', 'cov9 alert') RETURNING id::text`).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM alerts WHERE id=$1", alertID) })

	if w := jsonReq(r, http.MethodPost, "/alerts/"+alertID+"/status", gin.H{"status": "investigating"}); w.Code >= 400 {
		t.Errorf("UpdateStatus = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_AlertClassifierHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAlertClassifierHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/alerts/classify-batch", h.BulkClassify)

	if w := jsonReq(r, http.MethodPost, "/alerts/classify-batch", gin.H{"limit": 5}); w.Code >= 400 {
		t.Errorf("BulkClassify = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_WebhooksHandler(t *testing.T) {
	db := testDB(t)
	// Dispatcher only used by CreateConfig; seed a row directly and exercise
	// Update/Toggle/Delete which are dispatcher-free.
	h := handlers.NewWebhooksHandler(nil, db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/webhooks/:id", h.UpdateConfig)
	r.PUT("/webhooks/:id/toggle", h.ToggleConfig)
	r.DELETE("/webhooks/:id", h.DeleteConfig)

	var whID string
	if err := db.Pool().QueryRow(contextBG(),
		`INSERT INTO webhook_configs (name, url, enabled) VALUES ('cov9-wh', 'https://example.com/h', true) RETURNING id::text`).Scan(&whID); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM webhook_configs WHERE id=$1", whID) })

	name := "cov9-wh-2"
	if w := jsonReq(r, http.MethodPut, "/webhooks/"+whID, gin.H{"name": name, "events": []string{"alert.created"}}); w.Code >= 400 {
		t.Errorf("UpdateConfig = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/webhooks/"+whID+"/toggle", nil); w.Code >= 400 {
		t.Errorf("ToggleConfig = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/webhooks/"+whID, nil); w.Code >= 400 {
		t.Errorf("DeleteConfig = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_MetricsReportHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewMetricsReportHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/schedules", h.CreateSchedule)
	r.PUT("/schedules/:id", h.UpdateSchedule)
	r.POST("/schedules/:id/toggle", h.ToggleSchedule)
	r.DELETE("/schedules/:id", h.DeleteSchedule)

	id := createID(t, r, "/schedules", gin.H{"name": "cov9-sched", "report_type": "operational", "schedule": "0 0 * * *"})
	if w := jsonReq(r, http.MethodPut, "/schedules/"+id, gin.H{"name": "cov9-sched-2", "output_format": "html"}); w.Code >= 400 {
		t.Errorf("UpdateSchedule = %d: %s", w.Code, w.Body.String())
	}
	postOK(t, r, "/schedules/"+id+"/toggle")
	delOK(t, r, "/schedules/"+id)
}

func TestCov9_SettingsHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSettingsHandler(db.Pool(), nil)
	r, _ := authRouter(t, db)
	r.PUT("/settings", h.Update)
	r.POST("/channels", h.CreateChannel)
	r.PUT("/channels/:id", h.UpdateChannel)
	r.DELETE("/channels/:id", h.DeleteChannel)

	if w := jsonReq(r, http.MethodPut, "/settings", gin.H{"cov9_key": "cov9_val"}); w.Code >= 400 {
		t.Errorf("Update settings = %d: %s", w.Code, w.Body.String())
	}
	chID := createID(t, r, "/channels", gin.H{"name": "cov9-chan", "type": "slack", "config": gin.H{"url": "x"}, "enabled": true, "min_severity": 3})
	if w := jsonReq(r, http.MethodPut, "/channels/"+chID, gin.H{"name": "cov9-chan-2", "type": "email", "enabled": false, "min_severity": 5}); w.Code >= 400 {
		t.Errorf("UpdateChannel = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/channels/"+chID)
}

func TestCov9_SOCTicketHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSOCTicketHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/tickets", h.Create)
	r.PUT("/tickets/:id", h.Update)
	r.POST("/tickets/:id/close", h.Close)
	r.POST("/tickets/:id/comments", h.AddComment)

	id := createID(t, r, "/tickets", gin.H{"title": "cov9 ticket", "description": "d", "priority": "high"})
	if w := jsonReq(r, http.MethodPut, "/tickets/"+id, gin.H{"title": "cov9 ticket upd", "status": "in_progress", "priority": "medium"}); w.Code >= 400 {
		t.Errorf("Update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPost, "/tickets/"+id+"/comments", gin.H{"content": "cov9 comment"}); w.Code >= 400 {
		t.Errorf("AddComment = %d: %s", w.Code, w.Body.String())
	}
	postOK(t, r, "/tickets/"+id+"/close")
}

func TestCov9_GeolocationHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewGeolocationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/geoip/bulk", h.BulkLookup)

	if w := jsonReq(r, http.MethodPost, "/geoip/bulk", gin.H{"ips": []string{"8.8.8.8", "1.1.1.1"}}); w.Code >= 400 {
		t.Errorf("BulkLookup = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_IOCEnrichmentHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIOCEnrichmentHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ioc/enrich/bulk", h.BulkEnrich)

	body := gin.H{"items": []gin.H{{"value": "1.2.3.4", "type": "ip"}}}
	if w := jsonReq(r, http.MethodPost, "/ioc/enrich/bulk", body); w.Code >= 400 {
		t.Errorf("BulkEnrich = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_DigestHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDigestHandler(nil, db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/digest/config", h.UpdateDigestConfig)

	cfg := gin.H{"daily": gin.H{"enabled": true, "send_time": "08:00", "min_severity": 5}}
	if w := jsonReq(r, http.MethodPut, "/digest/config", cfg); w.Code >= 400 {
		t.Errorf("UpdateDigestConfig = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_SoftwareInventoryHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSoftwareInventoryHandler(store.NewSoftwareInventoryStore(db))
	r, _ := authRouter(t, db)
	r.DELETE("/software/:id", h.DeleteEntry)

	// Non-existent (valid-uuid) entry: DELETE affects 0 rows without error -> 200.
	if w := jsonReq(r, http.MethodDelete, "/software/"+uuid.NewString(), nil); w.Code >= 400 {
		t.Errorf("DeleteEntry = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_UEBAHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewUEBAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/ueba/anomalies/:id/status", h.UpdateAnomalyStatus)

	var anomalyID string
	if err := db.Pool().QueryRow(contextBG(),
		`INSERT INTO ueba_anomalies (username, anomaly_type, severity, score, details, status)
		 VALUES ('cov9', 'spike', 'high', 5, '{}'::jsonb, 'open') RETURNING id::text`).Scan(&anomalyID); err != nil {
		t.Fatalf("seed ueba_anomaly: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM ueba_anomalies WHERE id=$1", anomalyID) })

	if w := jsonReq(r, http.MethodPut, "/ueba/anomalies/"+anomalyID+"/status", gin.H{"status": "reviewed", "notes": "cov9"}); w.Code >= 400 {
		t.Errorf("UpdateAnomalyStatus = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov9_TenantRolesHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewTenantRolesHandler(store.NewTenantRoleStore(db.Pool()))
	r, uid := authRouter(t, db)
	r.PUT("/tenants/:id/roles/:user_id", h.Upsert)
	r.DELETE("/tenants/:id/roles/:user_id", h.Delete)

	var tenantID string
	slug := "cov9-" + uuid.NewString()[:8]
	if err := db.Pool().QueryRow(contextBG(),
		`INSERT INTO tenants (name, slug, plan, max_agents, is_active)
		 VALUES ('cov9-tenant', $1, 'free', 10, true) RETURNING id::text`, slug).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM tenants WHERE id=$1", tenantID) })

	if w := jsonReq(r, http.MethodPut, "/tenants/"+tenantID+"/roles/"+uid, gin.H{"role": "analyst"}); w.Code >= 400 {
		t.Errorf("Upsert = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/tenants/"+tenantID+"/roles/"+uid, nil); w.Code >= 400 {
		t.Errorf("Delete = %d: %s", w.Code, w.Body.String())
	}
}
