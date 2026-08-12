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

// TestRiskRegisterHandler_Integration exercises the risk-register
// Create/List/Update/Delete handlers end-to-end against a real database.
func TestRiskRegisterHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewRiskRegisterHandler(pool)

	const title = "itest-risk"
	const renamed = "itest-risk-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM risk_register WHERE title = ANY($1)", []string{title, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/risks", h.List)
	r.POST("/risks", h.Create)
	r.PUT("/risks/:id", h.Update)
	r.DELETE("/risks/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create (inherent_risk_score = likelihood*impact = 20) ───────────────
	w := do(http.MethodPost, "/risks",
		`{"title":"`+title+`","category":"operational","likelihood":4,"impact":5,"owner":"secops","status":"active"}`)
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

	// ── Create with no title → 400 ──────────────────────────────────────────
	if w := do(http.MethodPost, "/risks", `{"category":"operational"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no title): expected 400, got %d", w.Code)
	}

	// ── Create with invalid status → 400 (validated, not 500) ───────────────
	if w := do(http.MethodPost, "/risks",
		`{"title":"`+title+`-bad","likelihood":3,"impact":3,"status":"bogus"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad status): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── Create with out-of-range likelihood → 400 ──────────────────────────
	if w := do(http.MethodPost, "/risks",
		`{"title":"`+title+`-bad","likelihood":9,"impact":3,"status":"active"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad likelihood): expected 400, got %d", w.Code)
	}

	// ── List includes the risk ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/risks", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update recomputes residual = inherent - inherent*ctrl/100 ───────────
	if w := do(http.MethodPut, "/risks/"+id,
		`{"title":"`+renamed+`","category":"operational","likelihood":3,"impact":3,"control_effectiveness":50,"risk_appetite":"within","owner":"secops","status":"mitigated"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/risks", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed risk not found")
	}

	// ── Update with invalid UUID → 400 ──────────────────────────────────────
	if w := do(http.MethodPut, "/risks/not-a-uuid", `{"title":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Update(bad id): expected 400, got %d", w.Code)
	}

	// ── Update with invalid risk_appetite → 400 (not a misleading 404) ──────
	// Regression: a CHECK-constraint-violating value used to surface as
	// "Risk not found" (404). It must now be a clear validation 400.
	if w := do(http.MethodPut, "/risks/"+id,
		`{"title":"`+renamed+`","likelihood":3,"impact":3,"risk_appetite":"aggressive","status":"active"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Update(invalid risk_appetite): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update with out-of-range likelihood → 400 ──────────────────────────
	if w := do(http.MethodPut, "/risks/"+id,
		`{"title":"`+renamed+`","likelihood":9,"impact":3,"risk_appetite":"within","status":"active"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Update(bad likelihood): expected 400, got %d", w.Code)
	}

	// ── Update omitting risk_appetite → 200 (defaults to 'within') ──────────
	// Previously this empty value violated the CHECK and returned a bogus 404.
	if w := do(http.MethodPut, "/risks/"+id,
		`{"title":"`+renamed+`","likelihood":2,"impact":2,"status":"active"}`); w.Code != http.StatusOK {
		t.Errorf("Update(omit risk_appetite): expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update a non-existent (but valid) UUID → 404 (genuinely not found) ──
	if w := do(http.MethodPut, "/risks/00000000-0000-0000-0000-000000000000",
		`{"title":"x","likelihood":2,"impact":2,"risk_appetite":"within","status":"active"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then List no longer contains it ───────────────────────
	if w := do(http.MethodDelete, "/risks/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/risks", ""); bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List after delete: risk %s should be gone", id)
	}
}
