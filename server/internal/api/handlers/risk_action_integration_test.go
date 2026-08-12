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

// TestRiskActionHandler_Integration exercises the risk-action-rule
// Create/List/Update/Delete handlers end-to-end against a real database.
func TestRiskActionHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewRiskActionHandler(pool)

	const name = "itest-risk-action"
	const renamed = "itest-risk-action-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM risk_action_rules WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ra", h.List)
	r.POST("/ra", h.Create)
	r.PUT("/ra/:id", h.Update)
	r.DELETE("/ra/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/ra", `{"name":"`+name+`","threshold":80,"action":"isolate","enabled":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Create: could not parse id: %v (%s)", err, w.Body.String())
	}
	id := created.ID

	// ── Create with no name → 400 ───────────────────────────────────────────
	if w := do(http.MethodPost, "/ra", `{"threshold":50}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Create with out-of-range threshold → 400 (binding max=100) ──────────
	if w := do(http.MethodPost, "/ra", `{"name":"x","threshold":200}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad threshold): expected 400, got %d", w.Code)
	}

	// ── Create with invalid action → 400 ────────────────────────────────────
	if w := do(http.MethodPost, "/ra", `{"name":"x","threshold":50,"action":"delete_everything"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad action): expected 400, got %d", w.Code)
	}

	// ── List includes the rule ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/ra", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the rule ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/ra/"+id, `{"name":"`+renamed+`","threshold":60,"action":"alert_only","enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ra/00000000-0000-0000-0000-000000000000", `{"name":"x","threshold":50,"action":"isolate"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/ra/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/ra/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
