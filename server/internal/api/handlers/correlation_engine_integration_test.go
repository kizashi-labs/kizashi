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
)

// TestCorrelationEngineHandler_Integration exercises the correlation-rule
// Create/Get/List/Toggle/Delete handlers end-to-end against a real database.
// Correlation rules pair a trigger event type with a follow event type within a
// time window — the core of the realtime alert correlator.
func TestCorrelationEngineHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewCorrelationEngineHandler(pool)

	const ruleName = "itest-correlation-rule"
	ctx := context.Background()
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM correlation_rules WHERE name=$1", ruleName) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ce", h.List)
	r.POST("/ce", h.Create)
	r.GET("/ce/:id", h.Get)
	r.POST("/ce/:id/toggle", h.Toggle)
	r.DELETE("/ce/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create: process → network within 5 minutes ─────────────────────────
	createBody := `{"name":"` + ruleName + `","description":"itest",` +
		`"trigger_event_type":"process","follow_event_type":"network",` +
		`"time_window_seconds":300,"same_agent":true,` +
		`"alert_title":"Suspicious process then network","alert_severity":8,"enabled":true}`
	w := do(http.MethodPost, "/ce", createBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Create: invalid JSON: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" || created["name"] != ruleName || created["enabled"] != true {
		t.Fatalf("Create: unexpected rule: %+v", created)
	}
	if created["trigger_event_type"] != "process" || created["follow_event_type"] != "network" {
		t.Errorf("Create: event types not persisted: %+v", created)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/ce/"+id, ""); w.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── List includes the rule ──────────────────────────────────────────────
	w = do(http.MethodGet, "/ce", "")
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List: created rule %s not found in response", id)
	}

	// ── Toggle flips enabled true → false ───────────────────────────────────
	w = do(http.MethodPost, "/ce/"+id+"/toggle", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Toggle: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var toggled map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &toggled)
	if toggled["enabled"] != false {
		t.Errorf("Toggle: enabled should flip to false, got %v", toggled["enabled"])
	}

	// ── Delete → 200, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/ce/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/ce/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
