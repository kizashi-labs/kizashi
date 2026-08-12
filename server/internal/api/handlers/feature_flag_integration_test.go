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

// TestFeatureFlagHandler_Integration exercises the feature-flag
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestFeatureFlagHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewFeatureFlagHandler(pool)

	const name = "itest_feature_flag"
	ctx := context.Background()
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM feature_flags WHERE name=$1", name) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ff", h.List)
	r.POST("/ff", h.Create)
	r.GET("/ff/:id", h.Get)
	r.PUT("/ff/:id", h.Update)
	r.DELETE("/ff/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/ff", `{"name":"`+name+`","description":"itest","enabled":true,"rollout_percentage":50}`)
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

	// ── Create with no name → 400 (binding required) ────────────────────────
	if w := do(http.MethodPost, "/ff", `{"description":"no name"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Create with an invalid name (hyphen) → 400 (regex) ──────────────────
	if w := do(http.MethodPost, "/ff", `{"name":"bad-name!"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad name): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/ff/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the flag ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/ff", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update disables the flag ────────────────────────────────────────────
	if w := do(http.MethodPut, "/ff/"+id, `{"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ff/00000000-0000-0000-0000-000000000000", `{"enabled":true}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/ff/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/ff/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
