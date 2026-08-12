package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// TestCustomAlertRulesHandler_Integration exercises the custom alert rule
// Create/Get/List/Toggle/Delete handlers end-to-end against a real database.
func TestCustomAlertRulesHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewCustomAlertRulesHandler(store.NewCustomAlertRuleStore(pool))

	const ruleName = "itest-custom-rule"
	ctx := context.Background()
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM custom_alert_rules WHERE name=$1", ruleName) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/rules", h.List)
	r.POST("/rules", h.Create)
	r.GET("/rules/:id", h.Get)
	r.PUT("/rules/:id", h.Update)
	r.POST("/rules/:id/toggle", h.Toggle)
	r.DELETE("/rules/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	// CreateCustomAlertRuleInput has no json tags → bind by Go field name.
	createBody := `{"Name":"` + ruleName + `","Description":"itest","EventType":"process",` +
		`"Conditions":[{"field":"image","op":"contains","value":"mimikatz"}],` +
		`"Severity":8,"AlertTitle":"Mimikatz detected","Enabled":true,` +
		`"ThresholdCount":1,"TimeWindowSeconds":300}`
	w := do(http.MethodPost, "/rules", createBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Create: invalid JSON: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" || created["name"] != ruleName || created["enabled"] != true {
		t.Fatalf("Create: unexpected rule payload: %+v", created)
	}
	if created["event_type"] != "process" || created["severity"] != float64(8) {
		t.Errorf("Create: fields not persisted: %+v", created)
	}

	// ── Create with out-of-range severity → 400 (CHECK 1-10, not 500) ───────
	badSeverity := `{"Name":"` + ruleName + `-bad","EventType":"process","Severity":99,` +
		`"AlertTitle":"x","ThresholdCount":1,"TimeWindowSeconds":300}`
	if w := do(http.MethodPost, "/rules", badSeverity); w.Code != http.StatusBadRequest {
		t.Errorf("Create(severity=99): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	w = do(http.MethodGet, "/rules/"+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── List includes the rule ──────────────────────────────────────────────
	w = do(http.MethodGet, "/rules", "")
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	var list struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	found := false
	for _, ru := range list.Rules {
		if ru["id"] == id {
			found = true
		}
	}
	if !found {
		t.Errorf("List: created rule %s not found", id)
	}

	// ── Toggle flips enabled true → false ───────────────────────────────────
	w = do(http.MethodPost, "/rules/"+id+"/toggle", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Toggle: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var toggled map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &toggled)
	if toggled["enabled"] != false {
		t.Errorf("Toggle: enabled should flip to false, got %v", toggled["enabled"])
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/rules/00000000-0000-0000-0000-000000000000",
		`{"Name":"x","EventType":"process","Severity":5,"ThresholdCount":1,"TimeWindowSeconds":60}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 204, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/rules/"+id, ""); w.Code != http.StatusNoContent {
		t.Errorf("Delete: expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/rules/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
