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

// TestKnowledgeBaseHandler_Integration exercises the knowledge-base-article
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestKnowledgeBaseHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewKnowledgeBaseHandler(pool)

	const title = "itest-kb-article"
	const renamed = "itest-kb-article-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM kb_articles WHERE title = ANY($1)", []string{title, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	// author_id is a non-null-ish uuid column; the handler reads it from the
	// auth context, so seed a valid UUID (no FK on the column).
	r.Use(func(c *gin.Context) { c.Set("user_id", "11111111-1111-1111-1111-111111111111") })
	r.GET("/kb", h.List)
	r.POST("/kb", h.Create)
	r.GET("/kb/:id", h.Get)
	r.PUT("/kb/:id", h.Update)
	r.DELETE("/kb/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/kb", `{"title":"`+title+`","category":"runbook","content":"# How to respond","published":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Create: could not parse id: %v (%s)", err, w.Body.String())
	}
	id := created.ID

	// ── Create with no content → 400 ────────────────────────────────────────
	if w := do(http.MethodPost, "/kb", `{"title":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no content): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/kb/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(title)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", title, w.Code, w.Body.String())
	}

	// ── List includes the article ──────────────────────────────────────────
	if w := do(http.MethodGet, "/kb", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the article ──────────────────────────────────────────
	if w := do(http.MethodPut, "/kb/"+id, `{"title":"`+renamed+`","category":"runbook","content":"# Updated","published":true}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/kb/"+id, ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("Get after update: renamed article not found")
	}

	// ── Delete → 200, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/kb/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/kb/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
