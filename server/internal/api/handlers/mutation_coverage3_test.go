package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// mutID POSTs body to path, accepts 200 or 201, and extracts an "id" either at
// the top level or nested one level inside a wrapper object. Handlers in this
// batch vary in their create-response shape, so this is more permissive than
// createID (which requires exactly 201 + {"id":...}).
func mutID(t *testing.T, r http.Handler, path string, body any) string {
	t.Helper()
	w := jsonReq(r, http.MethodPost, path, body)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("POST %s = %d\n%s", path, w.Code, w.Body.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("POST %s: unmarshal %s", path, w.Body.String())
	}
	var id string
	if raw, ok := m["id"]; ok {
		_ = json.Unmarshal(raw, &id)
	}
	if id == "" {
		// look one level into wrapper objects for an "id"
		for _, raw := range m {
			var inner map[string]json.RawMessage
			if json.Unmarshal(raw, &inner) == nil {
				if idRaw, ok := inner["id"]; ok {
					_ = json.Unmarshal(idRaw, &id)
					if id != "" {
						break
					}
				}
			}
		}
	}
	if id == "" {
		t.Fatalf("POST %s: no id in %s", path, w.Body.String())
	}
	return id
}

func TestFeatureFlagHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewFeatureFlagHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ff", h.Create)
	r.POST("/ff/:id/toggle", h.Toggle)
	r.DELETE("/ff/:id", h.Delete)
	id := mutID(t, r, "/ff", gin.H{"name": "cov_flag", "description": "d", "enabled": true, "rollout_percentage": 50})
	postOK(t, r, "/ff/"+id+"/toggle")
	delOK(t, r, "/ff/"+id)
}

func TestEDRPolicyHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewEDRPolicyHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/edrp", h.Create)
	r.POST("/edrp/:id/toggle", h.Toggle)
	r.DELETE("/edrp/:id", h.Delete)
	tr := true
	id := mutID(t, r, "/edrp", gin.H{"name": "cov-edrp", "description": "d", "policy_type": "prevention", "rules": gin.H{}, "enabled": &tr})
	postOK(t, r, "/edrp/"+id+"/toggle")
	delOK(t, r, "/edrp/"+id)
}

func TestIncidentPlaybookHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIncidentPlaybookHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ipb", h.Create)
	r.DELETE("/ipb/:id", h.Delete)
	id := mutID(t, r, "/ipb", gin.H{"name": "cov-ipb", "description": "d", "incident_type": "malware", "severity_threshold": 5, "steps": []gin.H{}})
	delOK(t, r, "/ipb/"+id)
}

func TestContextEnrichmentHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewContextEnrichmentHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ctx", h.CreateSource)
	r.POST("/ctx/:id/toggle", h.ToggleSource)
	r.DELETE("/ctx/:id", h.DeleteSource)
	id := mutID(t, r, "/ctx", gin.H{"name": "cov-ctx", "source_type": "virustotal", "daily_limit": 1000, "avg_latency_ms": 50})
	postOK(t, r, "/ctx/"+id+"/toggle")
	delOK(t, r, "/ctx/"+id)
}

func TestHoneynetHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHoneynetHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/hn", h.CreateNode)
	r.POST("/hn/:id/toggle", h.ToggleNode)
	r.DELETE("/hn/:id", h.DeleteNode)
	id := mutID(t, r, "/hn", gin.H{"name": "cov-hn", "node_type": "server"})
	postOK(t, r, "/hn/"+id+"/toggle")
	delOK(t, r, "/hn/"+id)
}

func TestAutomationWorkflowsHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutomationWorkflowsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/aw", h.Create)
	r.DELETE("/aw/:id", h.Delete)
	id := mutID(t, r, "/aw", gin.H{"name": "cov-aw", "description": "d", "trigger": gin.H{}, "actions": gin.H{}, "status": "draft"})
	delOK(t, r, "/aw/"+id)
}

func TestKnowledgeBaseHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewKnowledgeBaseHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/kb", h.Create)
	r.DELETE("/kb/:id", h.Delete)
	id := mutID(t, r, "/kb", gin.H{"title": "cov-kb", "category": "general", "content": "body", "published": true})
	delOK(t, r, "/kb/"+id)
}

func TestCloudMonitorHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudMonitorHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/cm", h.CreateIntegration)
	r.DELETE("/cm/:id", h.DeleteIntegration)
	id := mutID(t, r, "/cm", gin.H{"name": "cov-cm", "provider": "aws", "region": "us-east-1", "config": gin.H{}})
	delOK(t, r, "/cm/"+id)
}

func TestComplianceEvidenceHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewComplianceEvidenceHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/cev", h.CreateTask)
	r.DELETE("/cev/:id", h.DeleteTask)
	id := mutID(t, r, "/cev", gin.H{"name": "cov-task", "framework": "SOC2", "control_id": "CC1.1", "description": "d", "collection_method": "manual", "schedule": "monthly"})
	delOK(t, r, "/cev/"+id)
}

func TestNetworkSegmentationHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNetworkSegmentationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ns", h.CreateSegment)
	r.DELETE("/ns/:id", h.DeleteSegment)
	id := mutID(t, r, "/ns", gin.H{"name": "cov-seg", "description": "d", "vlan_id": 10, "cidr": "10.0.0.0/24", "gateway": "10.0.0.1", "dns_servers": []string{"8.8.8.8"}, "status": "active"})
	delOK(t, r, "/ns/"+id)
}

func TestSOCTicketHandler_Create(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSOCTicketHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/st", h.Create)
	_ = mutID(t, r, "/st", gin.H{"title": "cov-ticket", "description": "d", "priority": "medium"})
}

func TestAdversaryEmulationHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAdversaryEmulationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ae", h.CreatePlan)
	r.DELETE("/ae/:id", h.DeletePlan)
	id := mutID(t, r, "/ae", gin.H{"plan_name": "cov-plan", "threat_actor_based_on": "APT29", "scope": "test", "status": "draft"})
	delOK(t, r, "/ae/"+id)
}

func TestEndpointTagHandler_Mutations(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()
	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-ettag', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })
	h := handlers.NewEndpointTagHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/et/:id/tags", h.AddTag)
	r.DELETE("/et/:id/tags/:tag", h.RemoveTag)
	if w := jsonReq(r, http.MethodPost, "/et/"+aid+"/tags", gin.H{"tag": "cov-tag", "color": "#fff"}); w.Code >= 400 {
		t.Fatalf("AddTag = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/et/"+aid+"/tags/cov-tag", nil); w.Code >= 400 {
		t.Fatalf("RemoveTag = %d: %s", w.Code, w.Body.String())
	}
}

func contextBG() context.Context { return context.Background() }

func TestFIMPageHandler_IgnoreRuleCRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewFIMPageHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/fimp/ignore", h.CreateIgnoreRule)
	r.DELETE("/fimp/ignore/:id", h.DeleteIgnoreRule)
	id := mutID(t, r, "/fimp/ignore", gin.H{"pattern": "/tmp/*", "reason": "noise"})
	delOK(t, r, "/fimp/ignore/"+id)
}
