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

// TestIncidentPlaybookHandler_Integration exercises the incident-playbook
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestIncidentPlaybookHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewIncidentPlaybookHandler(pool)

	const name = "itest-playbook"
	const renamed = "itest-playbook-renamed"
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM incident_playbooks WHERE name = ANY($1)", []string{name, renamed})
	}
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ipb", h.List)
	r.POST("/ipb", h.Create)
	r.GET("/ipb/:id", h.Get)
	r.PUT("/ipb/:id", h.Update)
	r.DELETE("/ipb/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/ipb",
		`{"name":"`+name+`","incident_type":"malware","severity_threshold":7,"steps":[{"action":"isolate"}],"enabled":true}`)
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
	if w := do(http.MethodPost, "/ipb", `{"incident_type":"malware"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/ipb/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the playbook ──────────────────────────────────────────
	if w := do(http.MethodGet, "/ipb", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update renames the playbook ─────────────────────────────────────────
	if w := do(http.MethodPut, "/ipb/"+id,
		`{"name":"`+renamed+`","incident_type":"ransomware","severity_threshold":9,"steps":[],"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/ipb/00000000-0000-0000-0000-000000000000",
		`{"name":"x","steps":[]}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/ipb/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/ipb/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
