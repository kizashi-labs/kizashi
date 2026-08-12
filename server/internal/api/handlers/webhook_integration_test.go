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

// TestWebhookHandler_Integration exercises the webhook-target
// List/Create/Update/Delete handlers end-to-end against a real database.
// Note: this handler maps "not found" to 500 (no row-count distinction), so we
// assert the happy path and verify removal via List rather than 404 codes.
func TestWebhookHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewWebhookHandler(store.NewWebhookStore(pool), nil)

	const name = "itest-webhook"
	const renamed = "itest-webhook-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM webhook_targets WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/wh", h.List)
	r.POST("/wh", h.Create)
	r.PUT("/wh/:id", h.Update)
	r.DELETE("/wh/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/wh", `{"name":"`+name+`","url":"https://example.com/hook","events":["alert.critical"],"enabled":true}`)
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

	// ── Create with no url → 400 (binding required) ─────────────────────────
	if w := do(http.MethodPost, "/wh", `{"name":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no url): expected 400, got %d", w.Code)
	}

	// ── List includes the webhook ───────────────────────────────────────────
	if w := do(http.MethodGet, "/wh", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the webhook ──────────────────────────────────────────
	if w := do(http.MethodPut, "/wh/"+id, `{"name":"`+renamed+`","url":"https://example.com/hook2","events":["alert.high"],"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/wh", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed webhook not found")
	}

	// ── Delete → 200, then List no longer contains it ───────────────────────
	if w := do(http.MethodDelete, "/wh/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/wh", ""); bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List after delete: webhook %s should be gone", id)
	}
}
