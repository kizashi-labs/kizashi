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

// TestSuppressionRuleHandler_Integration exercises the alert-suppression-rule
// Create/Get/List/Update/Toggle/Delete handlers end-to-end against a real database.
func TestSuppressionRuleHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewSuppressionRuleHandler(store.NewSuppressionRuleStore(pool))

	const name = "itest-suppression"
	const renamed = "itest-suppression-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM alert_suppression_rules WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/rules", h.List)
	r.GET("/rules/:id", h.Get)
	r.POST("/rules", h.Create)
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
	w := do(http.MethodPost, "/rules", `{"name":"`+name+`","pattern":"noisy.*alert","enabled":true}`)
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

	// ── Create with no name/pattern → 400 (binding:"required") ──────────────
	if w := do(http.MethodPost, "/rules", `{"description":"missing required fields"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(invalid): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/rules/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the rule ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/rules", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update renames the rule ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/rules/"+id, `{"name":"`+renamed+`","pattern":"noisy.*alert","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/rules/"+id, ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("Get after update: renamed rule not found")
	}

	// ── Toggle flips enabled true → false ───────────────────────────────────
	w = do(http.MethodPost, "/rules/"+id+"/toggle", "")
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

	// ── Delete → 200, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/rules/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/rules/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
