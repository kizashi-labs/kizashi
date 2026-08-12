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

// TestAgentPolicyHandler_Integration exercises the agent-policy
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestAgentPolicyHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewAgentPolicyHandler(store.NewAgentPolicyStore(pool))

	const name = "itest-agent-policy"
	const renamed = "itest-agent-policy-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM agent_policies WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ap", h.List)
	r.POST("/ap", h.Create)
	r.GET("/ap/:id", h.Get)
	r.PUT("/ap/:id", h.Update)
	r.DELETE("/ap/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create (applyDefaults fills the rest of the required fields) ────────
	w := do(http.MethodPost, "/ap", `{"name":"`+name+`","description":"itest"}`)
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
	if w := do(http.MethodPost, "/ap", `{"description":"no name"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Create with out-of-range scan_interval_min → 400 ────────────────────
	if w := do(http.MethodPost, "/ap", `{"name":"x","scan_interval_min":2}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad scan_interval): expected 400, got %d", w.Code)
	}

	// ── Create with invalid log_level → 400 ─────────────────────────────────
	if w := do(http.MethodPost, "/ap", `{"name":"x","log_level":"verbose"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad log_level): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/ap/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the policy ────────────────────────────────────────────
	if w := do(http.MethodGet, "/ap", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update renames the policy ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ap/"+id, `{"name":"`+renamed+`","description":"updated"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ap/00000000-0000-0000-0000-000000000000", `{"name":"x"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/ap/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/ap/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
