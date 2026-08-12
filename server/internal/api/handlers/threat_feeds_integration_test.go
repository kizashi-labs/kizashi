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

// TestThreatFeedHandler_Integration exercises the threat-feed
// List/Create/Update/Delete handlers end-to-end against a real database.
func TestThreatFeedHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	h := handlers.NewThreatFeedHandler(store.NewThreatFeedStore(db), store.NewIOCStore(db))

	const name = "itest-threat-feed"
	const renamed = "itest-threat-feed-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = db.Pool().Exec(ctx, "DELETE FROM threat_feeds WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/tf", h.List)
	r.POST("/tf", h.Create)
	r.PUT("/tf/:id", h.Update)
	r.DELETE("/tf/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/tf", `{"name":"`+name+`","url":"https://feeds.example/list.txt","ioc_type":"ip","feed_type":"txt"}`)
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
	if w := do(http.MethodPost, "/tf", `{"name":"x","ioc_type":"ip"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no url): expected 400, got %d", w.Code)
	}

	// ── Create with no ioc_type → 400 (binding required) ────────────────────
	if w := do(http.MethodPost, "/tf", `{"name":"x","url":"https://x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no ioc_type): expected 400, got %d", w.Code)
	}

	// ── List includes the feed ──────────────────────────────────────────────
	if w := do(http.MethodGet, "/tf", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the feed ─────────────────────────────────────────────
	if w := do(http.MethodPut, "/tf/"+id, `{"name":"`+renamed+`","url":"https://feeds.example/list.txt","ioc_type":"ip"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/tf", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed feed not found")
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/tf/00000000-0000-0000-0000-000000000000",
		`{"name":"x","url":"https://x","ioc_type":"ip"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/tf/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/tf/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
