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

// TestMaintenanceWindowHandler_Integration exercises the maintenance-window
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestMaintenanceWindowHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewMaintenanceWindowHandler(store.NewMaintenanceWindowStore(pool))

	const name = "itest-mw"
	const renamed = "itest-mw-renamed"
	const start = "2030-01-01T00:00:00Z"
	const end = "2030-01-01T02:00:00Z"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM maintenance_windows WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/mw", h.List)
	r.POST("/mw", h.Create)
	r.GET("/mw/:id", h.Get)
	r.PUT("/mw/:id", h.Update)
	r.DELETE("/mw/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/mw", `{"name":"`+name+`","start_time":"`+start+`","end_time":"`+end+`"}`)
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

	// ── Create with end_time before start_time → 400 ────────────────────────
	if w := do(http.MethodPost, "/mw", `{"name":"`+name+`","start_time":"`+end+`","end_time":"`+start+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(end<start): expected 400, got %d", w.Code)
	}

	// ── Create with malformed time → 400 ────────────────────────────────────
	if w := do(http.MethodPost, "/mw", `{"name":"`+name+`","start_time":"not-a-time","end_time":"`+end+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad time): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/mw/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the window ────────────────────────────────────────────
	if w := do(http.MethodGet, "/mw", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update renames the window ───────────────────────────────────────────
	if w := do(http.MethodPut, "/mw/"+id, `{"name":"`+renamed+`","start_time":"`+start+`","end_time":"`+end+`"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/mw/00000000-0000-0000-0000-000000000000",
		`{"name":"x","start_time":"`+start+`","end_time":"`+end+`"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/mw/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/mw/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
