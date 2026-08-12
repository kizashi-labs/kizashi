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

// TestSavedHuntHandler_Integration exercises the saved-hunt-query
// List/Create/Update/Delete handlers end-to-end against a real database.
func TestSavedHuntHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewSavedHuntHandler(store.NewSavedHuntStore(pool))

	const name = "itest-saved-hunt"
	const renamed = "itest-saved-hunt-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM saved_hunt_queries WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/saved", h.List)
	r.POST("/saved", h.Create)
	r.PUT("/saved/:id", h.Update)
	r.DELETE("/saved/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	// is_shared=true so List (which filters by owner OR shared) returns it even
	// without an authenticated user_id in the test context.
	w := do(http.MethodPost, "/saved", `{"name":"`+name+`","query":"SELECT 1","query_type":"sql","is_shared":true}`)
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

	// ── Create with no query → 400 ──────────────────────────────────────────
	if w := do(http.MethodPost, "/saved", `{"name":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no query): expected 400, got %d", w.Code)
	}

	// ── List includes the query ─────────────────────────────────────────────
	if w := do(http.MethodGet, "/saved", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the query ────────────────────────────────────────────
	if w := do(http.MethodPut, "/saved/"+id, `{"name":"`+renamed+`","query":"SELECT 2","is_shared":true}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/saved", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed query not found")
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/saved/00000000-0000-0000-0000-000000000000", `{"name":"x","query":"SELECT 3"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/saved/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/saved/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
