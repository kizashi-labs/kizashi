package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// seedTestUser inserts a user (some Create handlers stamp created_by) and
// returns its id, registering cleanup.
func seedTestUser(t *testing.T, db *store.DB) string {
	t.Helper()
	id := uuid.NewString()
	ctx := context.Background()
	if _, err := db.Pool().Exec(ctx,
		"INSERT INTO users (id, email) VALUES ($1, $2)", id, "cov-"+id[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", id) })
	return id
}

// jsonReq issues a JSON request against r and returns the recorder.
func jsonReq(r http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// createID POSTs body to path, asserts 201, and returns the created "id".
func createID(t *testing.T, r http.Handler, path string, body any) string {
	t.Helper()
	w := jsonReq(r, http.MethodPost, path, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST %s = %d, want 201\n%s", path, w.Code, w.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == "" {
		t.Fatalf("POST %s: could not read id from %s", path, w.Body.String())
	}
	return resp.ID
}

// authRouter returns a gin router with a seeded, injected user.
func authRouter(t *testing.T, db *store.DB) (*gin.Engine, string) {
	uid := seedTestUser(t, db)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", uid); c.Next() })
	return r, uid
}

func TestDataClassificationHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDataClassificationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/labels", h.CreateLabel)
	r.PUT("/labels/:id", h.UpdateLabel)
	r.DELETE("/labels/:id", h.DeleteLabel)
	r.POST("/assets", h.CreateAsset)
	r.PUT("/assets/:id", h.UpdateAsset)
	r.DELETE("/assets/:id", h.DeleteAsset)
	r.POST("/policies", h.CreatePolicy)

	labelID := createID(t, r, "/labels", gin.H{"name": "cov-label", "level": 2, "color": "#ff0000"})
	if w := jsonReq(r, http.MethodPut, "/labels/"+labelID, gin.H{"name": "cov-label-2", "level": 3, "color": "#00ff00", "description": "d", "handling_rules": "h", "is_active": true}); w.Code >= 400 {
		t.Errorf("update label = %d: %s", w.Code, w.Body.String())
	}

	assetID := createID(t, r, "/assets", gin.H{"name": "cov-asset", "type": "database"})
	if w := jsonReq(r, http.MethodPut, "/assets/"+assetID, gin.H{"name": "cov-asset-2", "type": "file"}); w.Code >= 400 {
		t.Errorf("update asset = %d: %s", w.Code, w.Body.String())
	}

	_ = createID(t, r, "/policies", gin.H{"name": "cov-policy", "classification_level": "confidential", "file_extensions": []string{".docx"}})

	for _, p := range []string{"/assets/" + assetID, "/labels/" + labelID} {
		if w := jsonReq(r, http.MethodDelete, p, nil); w.Code >= 400 {
			t.Errorf("delete %s = %d: %s", p, w.Code, w.Body.String())
		}
	}
}

func TestDeceptionHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDeceptionHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/traps", h.CreateTrap)
	r.PUT("/traps/:id", h.UpdateTrap)
	r.POST("/traps/:id/toggle", h.ToggleTrap)
	r.DELETE("/traps/:id", h.DeleteTrap)
	r.POST("/assets", h.CreateAsset)

	trapID := createID(t, r, "/traps", gin.H{"name": "cov-trap", "type": "file"})
	if w := jsonReq(r, http.MethodPut, "/traps/"+trapID, gin.H{"name": "cov-trap-2", "type": "credential", "target_path": "/tmp/x", "description": "d", "is_active": true}); w.Code >= 400 {
		t.Errorf("update trap = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPost, "/traps/"+trapID+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle trap = %d: %s", w.Code, w.Body.String())
	}
	_ = createID(t, r, "/assets", gin.H{"name": "cov-decoy", "asset_type": "honeypot", "description": "d", "emulated_service": "ssh", "listen_port": 22, "alert_on_access": true})
	if w := jsonReq(r, http.MethodDelete, "/traps/"+trapID, nil); w.Code >= 400 {
		t.Errorf("delete trap = %d: %s", w.Code, w.Body.String())
	}
}

func TestGDPRHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewGDPRHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/subjects", h.CreateSubject)
	r.PUT("/subjects/:id", h.UpdateSubject)
	r.DELETE("/subjects/:id", h.DeleteSubject)
	r.POST("/incidents", h.CreateIncident)
	r.PUT("/incidents/:id", h.UpdateIncident)

	subID := createID(t, r, "/subjects", gin.H{"subject_type": "customer", "email": "cov-subj@example.com", "name": "Cov Subject"})
	if w := jsonReq(r, http.MethodPut, "/subjects/"+subID, gin.H{"email": "cov-subj2@example.com", "name": "Updated"}); w.Code >= 400 {
		t.Errorf("update subject = %d: %s", w.Code, w.Body.String())
	}

	incID := createID(t, r, "/incidents", gin.H{"incident_type": "breach", "description": "cov incident", "severity": "high"})
	if w := jsonReq(r, http.MethodPut, "/incidents/"+incID, gin.H{"description": "updated", "severity": "critical", "status": "resolved"}); w.Code >= 400 {
		t.Errorf("update incident = %d: %s", w.Code, w.Body.String())
	}

	if w := jsonReq(r, http.MethodDelete, "/subjects/"+subID, nil); w.Code >= 400 {
		t.Errorf("delete subject = %d: %s", w.Code, w.Body.String())
	}
}

func TestAPISecurityHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAPISecurityHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/endpoints", h.CreateEndpoint)
	r.PUT("/endpoints/:id", h.UpdateEndpoint)
	r.DELETE("/endpoints/:id", h.DeleteEndpoint)

	epID := createID(t, r, "/endpoints", gin.H{"service_name": "cov-svc", "method": "GET", "path": "/cov"})
	if w := jsonReq(r, http.MethodPut, "/endpoints/"+epID, gin.H{"service_name": "cov-svc", "method": "POST", "path": "/cov2", "auth_type": "jwt"}); w.Code >= 400 {
		t.Errorf("update endpoint = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/endpoints/"+epID, nil); w.Code >= 400 {
		t.Errorf("delete endpoint = %d: %s", w.Code, w.Body.String())
	}
}

// delOK issues DELETE p and fails on 4xx/5xx.
func delOK(t *testing.T, r http.Handler, p string) {
	t.Helper()
	if w := jsonReq(r, http.MethodDelete, p, nil); w.Code >= 400 {
		t.Errorf("DELETE %s = %d: %s", p, w.Code, w.Body.String())
	}
}

// postOK issues POST p and fails on 4xx/5xx (for toggle-style endpoints).
func postOK(t *testing.T, r http.Handler, p string) {
	t.Helper()
	if w := jsonReq(r, http.MethodPost, p, nil); w.Code >= 400 {
		t.Errorf("POST %s = %d: %s", p, w.Code, w.Body.String())
	}
}

func TestContainerSecurityHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewContainerSecurityHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/p", h.CreatePolicy)
	r.POST("/p/:id/toggle", h.TogglePolicy)
	r.DELETE("/p/:id", h.DeletePolicy)
	id := createID(t, r, "/p", gin.H{"name": "cov-k8s", "policy_type": "network", "rules": gin.H{}, "enforcement": "warn"})
	postOK(t, r, "/p/"+id+"/toggle")
	delOK(t, r, "/p/"+id)
}

func TestDLPHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDLPHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/r", h.CreateRule)
	r.POST("/r/:id/toggle", h.ToggleRule)
	r.DELETE("/r/:id", h.DeleteRule)
	id := createID(t, r, "/r", gin.H{"name": "cov-dlp", "pattern": `\d{16}`, "pattern_type": "regex", "data_category": "pci", "action": "alert", "severity": 5, "enabled": true})
	postOK(t, r, "/r/"+id+"/toggle")
	delOK(t, r, "/r/"+id)
}

func TestHoneypotHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewHoneypotHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/h", h.Create)
	r.POST("/h/:id/toggle", h.Toggle)
	r.DELETE("/h/:id", h.Delete)
	id := createID(t, r, "/h", gin.H{"name": "cov-hp", "honeypot_type": "ssh", "listen_address": "0.0.0.0", "listen_port": 2222, "enabled": true, "alert_on_access": true})
	postOK(t, r, "/h/"+id+"/toggle")
	delOK(t, r, "/h/"+id)
}

func TestAutonomousPolicyHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAutonomousPolicyHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/p", h.CreatePolicy)
	r.POST("/p/:id/toggle", h.TogglePolicy)
	r.DELETE("/p/:id", h.DeletePolicy)
	id := createID(t, r, "/p", gin.H{"name": "cov-auto", "trigger_conditions": gin.H{"severity": "high"}, "response_actions": []string{"isolate"}, "requires_approval": false, "max_scope": "single_host"})
	postOK(t, r, "/p/"+id+"/toggle")
	delOK(t, r, "/p/"+id)
}

func TestBASHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewBASHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/s", h.CreateScenario)
	r.DELETE("/s/:id", h.DeleteScenario)
	id := createID(t, r, "/s", gin.H{"name": "cov-bas", "scenario_type": "ransomware", "mitre_tactics": []string{"TA0040"}, "mitre_techniques": []string{"T1486"}, "difficulty": "medium"})
	delOK(t, r, "/s/"+id)
}

func TestAttackSurfaceHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAttackSurfaceHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/a", h.CreateAsset)
	r.DELETE("/a/:id", h.DeleteAsset)
	id := createID(t, r, "/a", gin.H{"asset_type": "domain", "value": "cov.example.com", "source": "manual", "risk_score": 10})
	delOK(t, r, "/a/"+id)
}

func TestVendorRiskHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewVendorRiskHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/v", h.CreateVendor)
	r.PUT("/v/:id", h.UpdateVendor)
	r.DELETE("/v/:id", h.DeleteVendor)
	id := createID(t, r, "/v", gin.H{"name": "cov-vendor", "category": "cloud", "status": "active"})
	if w := jsonReq(r, http.MethodPut, "/v/"+id, gin.H{"name": "cov-vendor-2", "category": "saas", "status": "active"}); w.Code >= 400 {
		t.Errorf("update vendor = %d: %s", w.Code, w.Body.String())
	}
	delOK(t, r, "/v/"+id)
}

func TestCloudIdentityHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudIdentityHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/pr", h.CreateProvider)
	r.DELETE("/pr/:id", h.DeleteProvider)
	id := createID(t, r, "/pr", gin.H{"name": "cov-idp", "provider_type": "aws", "tenant_id": "t-1", "config": gin.H{"region": "us-east-1"}})
	delOK(t, r, "/pr/"+id)
}

func TestZeroTrustHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewZeroTrustHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	r.PUT("/policies/:id", h.UpdatePolicy)
	r.POST("/policies/:id/toggle", h.TogglePolicy)
	r.DELETE("/policies/:id", h.DeletePolicy)

	pid := createID(t, r, "/policies", gin.H{"name": "cov-zt", "action": "deny", "policy_type": "network", "priority": 50})
	if w := jsonReq(r, http.MethodPut, "/policies/"+pid, gin.H{"name": "cov-zt-2", "description": "d", "policy_type": "network", "conditions": gin.H{}, "action": "allow", "priority": 60, "enabled": true}); w.Code >= 400 {
		t.Errorf("update zt policy = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodPost, "/policies/"+pid+"/toggle", nil); w.Code >= 400 {
		t.Errorf("toggle zt policy = %d: %s", w.Code, w.Body.String())
	}
	if w := jsonReq(r, http.MethodDelete, "/policies/"+pid, nil); w.Code >= 400 {
		t.Errorf("delete zt policy = %d: %s", w.Code, w.Body.String())
	}
}
