package handlers_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/reports"
	"github.com/edr-platform/server/internal/store"
)

func TestCov6_AdminReportSchedules(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAdminReportSchedulesHandler(reports.NewScheduler(db.Pool(), nil, nil))
	r, _ := authRouter(t, db)
	r.POST("/ars", h.Create)
	r.PUT("/ars/:id", h.Update)
	r.PUT("/ars/:id/toggle", h.Toggle)
	r.DELETE("/ars/:id", h.Delete)

	id := mutID(t, r, "/ars", gin.H{"name": "cov-ars", "report_type": "executive_summary", "schedule": "0 8 * * 1"})
	if w := jsonReq(r, http.MethodPut, "/ars/"+id, gin.H{"name": "cov-ars-2", "report_type": "executive_summary", "schedule": "0 9 * * 1"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/ars/"+id+"/toggle", gin.H{"enabled": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/ars/"+id)
}

func TestCov6_AlertAssign(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAlertAssignHandler(store.NewAlertAssignRuleStore(db.Pool()))
	r, uid := authRouter(t, db)
	r.POST("/aa", h.Create)
	r.PUT("/aa/:id", h.Update)
	r.DELETE("/aa/:id", h.Delete)

	id := mutID(t, r, "/aa", gin.H{"name": "cov-aa", "priority": 5, "assignee_id": uid, "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/aa/"+id, gin.H{"name": "cov-aa-2", "priority": 6, "assignee_id": uid, "enabled": false}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/aa/"+id)
}

func TestCov6_Backup(t *testing.T) {
	db := testDB(t)
	dir := t.TempDir()
	h := handlers.NewBackupHandler("postgres://edr@localhost:5433/edrplatform_test", dir)
	r, _ := authRouter(t, db)
	r.POST("/b", h.Create)
	r.DELETE("/b/:name", h.Delete)

	if w := jsonReq(r, http.MethodPost, "/b", nil); w.Code >= 400 {
		t.Errorf("create backup = %d: %s", w.Code, w.Body.String())
	}
	name := "backup_cov.sql"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
		t.Fatalf("write backup file: %v", err)
	}
	delOK(t, r, "/b/"+name)
}

func TestCov6_Correlation(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()
	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov6-corr', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })

	h := handlers.NewCorrelationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/cr", h.Create)
	r.PUT("/cr/:id", h.Update)
	r.PUT("/cr/:id/toggle", h.Toggle)
	r.DELETE("/cr/:id", h.Delete)

	id := createID(t, r, "/cr", gin.H{"agent_id": aid, "mitre_technique": "T1059", "alert_count": 2})
	if w := jsonReq(r, http.MethodPut, "/cr/"+id, gin.H{"agent_id": aid, "mitre_technique": "T1055", "alert_count": 3}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/cr/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/cr/"+id)
}

func TestCov6_FIM(t *testing.T) {
	db := testDB(t)
	h := handlers.NewFIMHandler(store.NewFIMRuleStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/fim", h.Create)
	r.PUT("/fim/:id", h.Update)
	r.PATCH("/fim/:id/toggle", h.Toggle)
	r.DELETE("/fim/:id", h.Delete)

	id := mutID(t, r, "/fim", gin.H{"name": "cov-fim", "path": "/etc", "severity": "high", "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/fim/"+id, gin.H{"name": "cov-fim-2", "path": "/var", "severity": "medium"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/fim/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/fim/"+id)
}

func TestCov6_IncidentDrills(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIncidentDrillsHandler(db.Pool())
	r, _ := authRouter(t, db)
	tid := uuid.NewString()
	r.Use(func(c *gin.Context) { c.Set("tenant_id", tid); c.Next() })
	r.POST("/dr", h.Create)
	r.PUT("/dr/:id", h.Update)
	r.DELETE("/dr/:id", h.Delete)

	id := mutID(t, r, "/dr", gin.H{"name": "cov-drill", "drill_type": "tabletop", "participants": []string{"a"}})
	if w := jsonReq(r, http.MethodPut, "/dr/"+id, gin.H{"status": "completed", "overall_score": 90}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/dr/"+id)
}

func TestCov6_Invitation(t *testing.T) {
	db := testDB(t)
	h := handlers.NewInvitationHandler(store.NewInvitationStore(db), store.NewUserStore(db), "http://localhost", nil)
	r, _ := authRouter(t, db)
	r.POST("/inv", h.Create)
	r.DELETE("/inv/:id", h.Delete)

	email := "cov-inv-" + uuid.NewString()[:8] + "@example.com"
	if w := jsonReq(r, http.MethodPost, "/inv", gin.H{"email": email, "role": "analyst"}); w.Code >= 400 {
		t.Fatalf("create invitation = %d: %s", w.Code, w.Body.String())
	}
	var id string
	if err := db.Pool().QueryRow(contextBG(),
		`SELECT id::text FROM user_invitations WHERE email=$1 ORDER BY created_at DESC LIMIT 1`, email).Scan(&id); err != nil {
		t.Fatalf("lookup invitation: %v", err)
	}
	delOK(t, r, "/inv/"+id)
}

func TestCov6_Notification(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNotificationHandler(store.NewAlertNotifStore(db.Pool()), nil)
	r, _ := authRouter(t, db)
	r.POST("/n", h.Create)
	r.PUT("/n/:id", h.Update)
	r.DELETE("/n/:id", h.Delete)

	id := mutID(t, r, "/n", gin.H{"name": "cov-notif", "type": "webhook_generic", "config": gin.H{"webhook_url": "http://localhost/x"}, "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/n/"+id, gin.H{"name": "cov-notif-2", "type": "webhook_slack", "config": gin.H{"webhook_url": "http://localhost/y"}}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/n/"+id)
}

func TestCov6_Playbooks(t *testing.T) {
	db := testDB(t)
	h := handlers.NewPlaybookHandler(store.NewPlaybookStore(db))
	r, _ := authRouter(t, db)
	r.POST("/pb", h.Create)
	r.PUT("/pb/:id", h.Update)
	r.PUT("/pb/:id/toggle", h.Toggle)
	r.DELETE("/pb/:id", h.Delete)

	actions := []gin.H{{"type": "notify", "message": "cov"}}
	id := mutID(t, r, "/pb", gin.H{"name": "cov-pb", "description": "d", "actions": actions, "is_active": true})
	if w := jsonReq(r, http.MethodPut, "/pb/"+id, gin.H{"name": "cov-pb-2", "actions": actions, "is_active": true}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/pb/"+id+"/toggle", gin.H{"is_active": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/pb/"+id)
}

func TestCov6_ReportSchedules(t *testing.T) {
	db := testDB(t)
	h := handlers.NewReportScheduleHandler(store.NewReportScheduleStore(db))
	r, _ := authRouter(t, db)
	r.POST("/rs", h.Create)
	r.PUT("/rs/:id", h.Update)
	r.PUT("/rs/:id/toggle", h.Toggle)
	r.DELETE("/rs/:id", h.Delete)

	id := mutID(t, r, "/rs", gin.H{"name": "cov-rs", "report_type": "summary", "frequency": "daily", "hour": 8, "recipients": []string{"cov@example.com"}})
	if w := jsonReq(r, http.MethodPut, "/rs/"+id, gin.H{"name": "cov-rs-2", "report_type": "summary", "frequency": "weekly", "hour": 9, "is_active": true}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/rs/"+id+"/toggle", gin.H{"is_active": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/rs/"+id)
}

func TestCov6_ReportTemplate(t *testing.T) {
	db := testDB(t)
	h := handlers.NewReportTemplateHandler(store.NewReportTemplateStore(db.Pool()), db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rt", h.Create)
	r.PUT("/rt/:id", h.Update)
	r.DELETE("/rt/:id", h.Delete)

	id := mutID(t, r, "/rt", gin.H{"name": "cov-rt", "description": "d", "format": "pdf"})
	if w := jsonReq(r, http.MethodPut, "/rt/"+id, gin.H{"name": "cov-rt-2", "format": "html"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/rt/"+id)
}

func TestCov6_Rules(t *testing.T) {
	db := testDB(t)
	h := handlers.NewRuleHandler(store.NewRuleStore(db))
	r, _ := authRouter(t, db)
	r.POST("/ru", h.Create)
	r.PUT("/ru/:id", h.Update)
	r.PUT("/ru/:id/toggle", h.Toggle)
	r.DELETE("/ru/:id", h.Delete)

	content := "title: cov\ndetection:\n  condition: selection\n"
	id := mutID(t, r, "/ru", gin.H{"name": "cov-rule", "type": "sigma", "content": content, "severity": 5, "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/ru/"+id, gin.H{"severity": 7}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPut, "/ru/"+id+"/toggle", gin.H{"enabled": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/ru/"+id)
}

func TestCov6_SIEM(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSIEMHandler(store.NewSIEMStore(db), nil)
	r, _ := authRouter(t, db)
	r.POST("/siem", h.Create)
	r.PUT("/siem/:id", h.Update)
	r.DELETE("/siem/:id", h.Delete)

	id := mutID(t, r, "/siem", gin.H{"name": "cov-siem", "type": "splunk_hec", "host": "localhost", "port": 8088, "protocol": "tcp"})
	if w := jsonReq(r, http.MethodPut, "/siem/"+id, gin.H{"name": "cov-siem-2", "type": "splunk_hec", "host": "127.0.0.1", "port": 8089, "protocol": "tcp"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/siem/"+id)
}

func TestCov6_Suppressions(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSuppressionHandler(store.NewSuppressionStore(db))
	r, _ := authRouter(t, db)
	r.POST("/sup", h.Create)
	r.PUT("/sup/:id/toggle", h.Toggle)
	r.DELETE("/sup/:id", h.Delete)

	name := "cov-sup-" + uuid.NewString()[:8]
	if w := jsonReq(r, http.MethodPost, "/sup", gin.H{"name": name, "description": "d", "conditions": gin.H{"rule_name": "x"}, "duration_h": 2}); w.Code >= 400 {
		t.Fatalf("create suppression = %d: %s", w.Code, w.Body.String())
	}
	var id string
	if err := db.Pool().QueryRow(contextBG(),
		`SELECT id::text FROM suppression_rules WHERE name=$1 ORDER BY created_at DESC LIMIT 1`, name).Scan(&id); err != nil {
		t.Fatalf("lookup suppression: %v", err)
	}
	if w := jsonReq(r, http.MethodPut, "/sup/"+id+"/toggle", gin.H{"is_active": false}); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/sup/"+id)
}

func TestCov6_Tenant(t *testing.T) {
	db := testDB(t)
	h := handlers.NewTenantHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/tn", h.Create)
	r.PATCH("/tn/:id", h.Update)
	r.DELETE("/tn/:id", h.Delete)

	slug := "cov-" + uuid.NewString()[:8]
	id := createID(t, r, "/tn", gin.H{"name": "cov-tenant", "slug": slug, "plan": "standard", "max_agents": 50})
	if w := jsonReq(r, http.MethodPatch, "/tn/"+id, gin.H{"plan": "enterprise", "max_agents": 200}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/tn/"+id)
}

func TestCov6_Users(t *testing.T) {
	db := testDB(t)
	h := handlers.NewUsersHandler(store.NewUserStore(db))
	r, _ := authRouter(t, db)
	r.POST("/u", h.Create)
	r.PUT("/u/:id", h.Update)
	r.DELETE("/u/:id", h.Deactivate)

	email := "cov-user-" + uuid.NewString()[:8] + "@example.com"
	id := mutID(t, r, "/u", gin.H{"email": email, "password": "coverage-pw-123", "full_name": "Cov User", "role": "analyst"})
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM users WHERE id=$1", id) })
	if w := jsonReq(r, http.MethodPut, "/u/"+id, gin.H{"role": "viewer"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/u/"+id)
}

func TestCov6_Vulnerabilities(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()
	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov6-vuln', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })

	h := handlers.NewVulnHandler(store.NewVulnStore(db))
	r, _ := authRouter(t, db)
	r.POST("/vu", h.Create)
	r.PUT("/vu/:id/status", h.UpdateStatus)
	r.DELETE("/vu/:id", h.Delete)

	id := mutID(t, r, "/vu", gin.H{"agent_id": aid, "cve_id": "CVE-2024-9999", "title": "cov vuln", "severity": "high", "description": "d"})
	if w := jsonReq(r, http.MethodPut, "/vu/"+id+"/status", gin.H{"status": "patched", "notes": "fixed"}); w.Code >= 400 {
		t.Errorf("update status = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/vu/"+id)
}

func TestCov6_YARA(t *testing.T) {
	db := testDB(t)
	h := handlers.NewYARAHandler(store.NewYARAStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/y", h.Create)
	r.PUT("/y/:id", h.Update)
	r.PATCH("/y/:id/toggle", h.Toggle)
	r.DELETE("/y/:id", h.Delete)

	content := "rule cov { condition: true }"
	id := mutID(t, r, "/y", gin.H{"name": "cov-yara", "content": content, "severity": "medium", "enabled": true})
	if w := jsonReq(r, http.MethodPut, "/y/"+id, gin.H{"name": "cov-yara-2", "content": content, "severity": "high"}); w.Code >= 400 {
		t.Errorf("update = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPatch, "/y/"+id+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/y/"+id)
}
