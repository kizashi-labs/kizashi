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

// TestEscalationRuleHandler_Integration exercises the alert-escalation-rule
// Create/List/Update/Toggle/Delete handlers end-to-end against a real database.
func TestEscalationRuleHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewEscalationRuleHandler(store.NewEscalationRuleStore(pool))

	const name = "itest-escalation"
	const renamed = "itest-escalation-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM alert_escalation_rules WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/esc", h.List)
	r.POST("/esc", h.Create)
	r.PUT("/esc/:id", h.Update)
	r.POST("/esc/:id/toggle", h.Toggle)
	r.DELETE("/esc/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/esc",
		`{"name":"`+name+`","severity_min":7,"unresolved_mins":30,"escalate_to":"tier2","enabled":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Create: could not parse id: %v (%s)", err, w.Body.String())
	}
	id := created.ID

	// ── Create with no escalate_to → 400 ────────────────────────────────────
	if w := do(http.MethodPost, "/esc", `{"name":"x","severity_min":5,"unresolved_mins":30}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no escalate_to): expected 400, got %d", w.Code)
	}

	// ── Create with out-of-range severity → 400 ─────────────────────────────
	if w := do(http.MethodPost, "/esc", `{"name":"x","severity_min":99,"unresolved_mins":30,"escalate_to":"tier2"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad severity): expected 400, got %d", w.Code)
	}

	// ── List includes the rule ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/esc", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the rule ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/esc/"+id,
		`{"name":"`+renamed+`","severity_min":8,"unresolved_mins":45,"escalate_to":"tier3","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/esc", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed rule not found")
	}

	// ── Toggle flips enabled true → false ───────────────────────────────────
	w = do(http.MethodPost, "/esc/"+id+"/toggle", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Toggle: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var toggled struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &toggled)
	if toggled.Enabled {
		t.Errorf("Toggle: enabled should flip to false, got true")
	}

	// ── Delete → 200, then List no longer contains it ───────────────────────
	if w := do(http.MethodDelete, "/esc/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/esc", ""); bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List after delete: rule %s should be gone", id)
	}
}
