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

// TestEDRPolicyHandler_Integration exercises the EDR-policy Create/Get/List/
// Toggle/Delete handlers end-to-end against a real database.
func TestEDRPolicyHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewEDRPolicyHandler(pool)

	const name = "itest-edr-policy"
	ctx := context.Background()
	cleanup := func() { _, _ = pool.Exec(ctx, "DELETE FROM edr_policies WHERE name=$1", name) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/policies", h.List)
	r.POST("/policies", h.Create)
	r.GET("/policies/:id", h.Get)
	r.POST("/policies/:id/toggle", h.Toggle)
	r.DELETE("/policies/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	w := do(http.MethodPost, "/policies",
		`{"name":"`+name+`","description":"itest","policy_type":"standard","rules":{"block_usb":true},"enabled":true}`)
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
	if w := do(http.MethodPost, "/policies", `{"description":"no name"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no name): expected 400, got %d", w.Code)
	}

	// ── Get ─────────────────────────────────────────────────────────────────
	if w := do(http.MethodGet, "/policies/"+id, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(name)) {
		t.Fatalf("Get: expected 200 containing %q, got %d: %s", name, w.Code, w.Body.String())
	}

	// ── List includes the policy ────────────────────────────────────────────
	if w := do(http.MethodGet, "/policies", ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(id)) {
		t.Fatalf("List: expected 200 containing %s, got %d", id, w.Code)
	}

	// ── Toggle flips enabled true → false ───────────────────────────────────
	w = do(http.MethodPost, "/policies/"+id+"/toggle", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Toggle: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var toggled map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &toggled)
	if toggled["enabled"] != false {
		t.Errorf("Toggle: enabled should flip to false, got %v", toggled["enabled"])
	}

	// ── Delete → 200, then Get → 404 ────────────────────────────────────────
	if w := do(http.MethodDelete, "/policies/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/policies/"+id, ""); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}
