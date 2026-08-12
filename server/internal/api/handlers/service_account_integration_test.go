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

// TestServiceAccountHandler_Integration exercises the service-account
// Create/Get/List/Update/Delete handlers end-to-end against a real database.
func TestServiceAccountHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewServiceAccountHandler(pool)

	const name = "itest-svc-account"
	ctx := context.Background()
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM service_accounts WHERE name=$1", name) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/sa", h.List)
	r.POST("/sa", h.Create)
	r.GET("/sa/:id", h.Get)
	r.PUT("/sa/:id", h.Update)
	r.DELETE("/sa/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create returns id + a one-time client_secret ────────────────────────
	w := do(http.MethodPost, "/sa", `{"name":"`+name+`","description":"itest","scopes":["read","write"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID           string `json:"id"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Create: could not parse id: %v (%s)", err, w.Body.String())
	}
	if created.ClientID == "" || created.ClientSecret == "" {
		t.Errorf("Create: client_id/client_secret should be returned once, got %+v", created)
	}
	id := created.ID

	// ── Create with no name → 400 ───────────────────────────────────────────
	if w := do(http.MethodPost, "/sa", `{"description":"no name"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/sa/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the account ───────────────────────────────────────────
	if w := do(http.MethodGet, "/sa", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Update disables the account ─────────────────────────────────────────
	if w := do(http.MethodPut, "/sa/"+id, `{"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Update non-existent → 404 ───────────────────────────────────────────
	if w := do(http.MethodPut, "/sa/00000000-0000-0000-0000-000000000000", `{"enabled":true}`); w.Code != http.StatusNotFound {
		t.Errorf("Update(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete → 200, then a second delete → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/sa/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/sa/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Delete(again): expected 404, got %d", w.Code)
	}
}
