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

// TestAutoResponseHandler_Integration exercises the auto-response-rule
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
// CreateAutoResponseRuleInput has no json tags → bind by Go field name.
func TestAutoResponseHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewAutoResponseHandler(store.NewAutoResponseStore(pool))

	const name = "itest-auto-response"
	const renamed = "itest-auto-response-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM auto_response_rules WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ar", h.List)
	r.POST("/ar", h.Create)
	r.GET("/ar/:id", h.Get)
	r.PUT("/ar/:id", h.Update)
	r.DELETE("/ar/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/ar",
		`{"Name":"`+name+`","ActionType":"isolate","TriggerSeverityMin":7,"Enabled":true,"ActionParams":{"reason":"itest"}}`)
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

	// ── Create with malformed JSON → 400 ────────────────────────────────────
	if w := do(http.MethodPost, "/ar", `{not-json`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(malformed): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/ar/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the rule ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/ar", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update renames the rule ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/ar/"+id,
		`{"Name":"`+renamed+`","ActionType":"isolate","TriggerSeverityMin":8,"Enabled":false,"ActionParams":{"reason":"updated"}}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ar/00000000-0000-0000-0000-000000000000",
		`{"Name":"x","ActionType":"isolate","ActionParams":{}}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 204, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/ar/"+id, ""); w.Code != http.StatusNoContent {
		t.Errorf("Delete: expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/ar/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
