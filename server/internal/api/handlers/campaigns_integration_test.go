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

// TestCampaignsHandler_Integration exercises the threat-campaign
// List/Create/Update/Delete handlers end-to-end against a real database.
// Update/Delete do not distinguish "not found", so removal is verified via List.
func TestCampaignsHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewCampaignsHandler(pool)

	const name = "itest-campaign"
	const renamed = "itest-campaign-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM threat_campaigns WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/cmp", h.List)
	r.POST("/cmp", h.Create)
	r.PUT("/cmp/:id", h.Update)
	r.DELETE("/cmp/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create (status/severity must satisfy the table CHECK) ───────────────
	w := do(http.MethodPost, "/cmp",
		`{"name":"`+name+`","threat_actor":"APT-itest","status":"active","severity":"high","techniques":["T1059"]}`)
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
	if w := do(http.MethodPost, "/cmp", `{"threat_actor":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── List includes the campaign ──────────────────────────────────────────
	if w := do(http.MethodGet, "/cmp", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d: %s", id, w.Code, w.Body.String())
	}

	// ── Update renames the campaign ─────────────────────────────────────────
	if w := do(http.MethodPut, "/cmp/"+id, `{"name":"`+renamed+`","status":"monitoring","severity":"critical"}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/cmp", ""); !bytes.Contains(w.Body.Bytes(), []byte(renamed)) {
		t.Errorf("List after update: renamed campaign not found")
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/cmp/00000000-0000-0000-0000-000000000000", `{"name":"x"}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/cmp/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/cmp", ""); bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Errorf("List after delete: campaign %s should be gone", id)
	}
	if w := do(http.MethodDelete, "/cmp/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
