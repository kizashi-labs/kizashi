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

// TestNotificationTemplateHandler_Integration exercises the notification-template
// List/Create/Update/Delete handlers end-to-end against a real database.
func TestNotificationTemplateHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewNotificationTemplateHandler(pool)

	const name = "itest-notif-tmpl"
	const renamed = "itest-notif-tmpl-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM notification_templates WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/templates", h.List)
	r.POST("/templates", h.Create)
	r.PUT("/templates/:id", h.Update)
	r.DELETE("/templates/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/templates", `{"name":"`+name+`","channel_type":"email","subject":"Hi","body":"Alert: {{.title}}"}`)
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

	// ── Create with no body → 400 ───────────────────────────────────────────
	if w := do(http.MethodPost, "/templates", `{"name":"x","channel_type":"email"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no body): expected 400, got %d", w.Code)
	}

	// ── List includes the template ──────────────────────────────────────────
	if w := do(http.MethodGet, "/templates", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the template ─────────────────────────────────────────
	if w := do(http.MethodPut, "/templates/"+id, `{"name":"`+renamed+`","body":"Updated: {{.title}}"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/templates", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed template not found")
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/templates/00000000-0000-0000-0000-000000000000", `{"name":"x","body":"y"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/templates/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/templates/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
