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

// TestProcessBlockHandler_Integration exercises the process-block-rule
// Create/List/Update/Delete handlers end-to-end against a real database.
func TestProcessBlockHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewProcessBlockHandler(store.NewProcessBlockRuleStore(pool))

	const name = "itest-pblock"
	const renamed = "itest-pblock-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM process_block_rules WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/pb", h.List)
	r.POST("/pb", h.Create)
	r.PUT("/pb/:id", h.Update)
	r.DELETE("/pb/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create (defaults applied for rule_type/scope/action/severity) ───────
	w := do(http.MethodPost, "/pb", `{"name":"`+name+`","process_name":"mimikatz.exe","rule_type":"deny","action":"block","severity":"critical"}`)
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
	if w := do(http.MethodPost, "/pb", `{"process_name":"x.exe"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Create with invalid rule_type → 400 (validateProcessBlockRequest) ───
	if w := do(http.MethodPost, "/pb", `{"name":"x","process_name":"y.exe","rule_type":"bogus"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(bad rule_type): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── List includes the rule ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/pb", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the rule ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/pb/"+id, `{"name":"`+renamed+`","process_name":"mimikatz.exe","rule_type":"deny","action":"block","severity":"high"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/pb", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed rule not found")
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/pb/00000000-0000-0000-0000-000000000000",
		`{"name":"x","process_name":"y.exe","rule_type":"deny","action":"alert","severity":"high"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/pb/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/pb/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
