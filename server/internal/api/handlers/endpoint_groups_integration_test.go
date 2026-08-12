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

// TestEndpointGroupsHandler_Integration exercises the endpoint-group
// List/Create/Update/Delete handlers end-to-end against a real database.
func TestEndpointGroupsHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewEndpointGroupsHandler(pool)

	const name = "itest-eg"
	const renamed = "itest-eg-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM endpoint_groups WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/groups", h.List)
	r.POST("/groups", h.Create)
	r.PUT("/groups/:id", h.Update)
	r.DELETE("/groups/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/groups", `{"name":"`+name+`","type":"custom","description":"itest"}`)
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
	if w := do(http.MethodPost, "/groups", `{"description":"no name"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Create with a non-existent parent_id → 400 (FK, not 500) ────────────
	if w := do(http.MethodPost, "/groups",
		`{"name":"`+name+`-fk","type":"custom","parent_id":"99999999-9999-9999-9999-999999999999"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad parent_id): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── List includes the group ─────────────────────────────────────────────
	if w := do(http.MethodGet, "/groups", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the group ────────────────────────────────────────────
	if w := do(http.MethodPut, "/groups/"+id, `{"name":"`+renamed+`","type":"custom","description":"updated"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/groups", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed group not found")
	}

	// ── Update an existing group with a bad parent_id → 400 (not a 404) ─────
	// Regression: the FK violation used to be conflated with "not found".
	if w := do(http.MethodPut, "/groups/"+id,
		`{"name":"`+renamed+`","type":"custom","parent_id":"99999999-9999-9999-9999-999999999999"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Update(bad parent_id): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/groups/00000000-0000-0000-0000-000000000000", `{"name":"x"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete, then List no longer contains it ─────────────────────────────
	if w := do(http.MethodDelete, "/groups/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/groups", ""); bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List after delete: group %s should be gone", id)
	}
}
