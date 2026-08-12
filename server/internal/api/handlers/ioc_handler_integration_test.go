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

// TestIOCHandler_Integration exercises the IOC Create/List/Check/Toggle/Delete
// handlers end-to-end against a real database.
func TestIOCHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	h := handlers.NewIOCHandler(store.NewIOCStore(db))

	const value = "203.0.113.45" // TEST-NET-3, valid IPv4
	ctx := context.Background()
	cleanup := func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM ioc_entries WHERE value=$1", value) }
	cleanup()
	t.Cleanup(cleanup)

	r := gin.New()
	r.GET("/ioc", h.List)
	r.POST("/ioc", h.Create)
	r.GET("/ioc/check", h.Check)
	r.PUT("/ioc/:id/toggle", h.Toggle)
	r.DELETE("/ioc/:id", h.Delete)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	if w := do(http.MethodPost, "/ioc", `{"type":"ip","value":"`+value+`","description":"itest","severity":8}`); w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// ── Create with no value → 400 ──────────────────────────────────────────
	if w := do(http.MethodPost, "/ioc", `{"type":"ip"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(no value): expected 400, got %d", w.Code)
	}

	// ── Create duplicate (same type+value) → 409 ────────────────────────────
	if w := do(http.MethodPost, "/ioc", `{"type":"ip","value":"`+value+`"}`); w.Code != http.StatusConflict {
		t.Errorf("Create(duplicate): expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// ── Create with a type outside the CHECK set → 400 (not 500) ────────────
	if w := do(http.MethodPost, "/ioc", `{"type":"banana","value":"`+value+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("Create(invalid type): expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── List returns the entry; capture its id ──────────────────────────────
	w := do(http.MethodGet, "/ioc?search="+value, "")
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	var listResp struct {
		Data []struct {
			ID       string `json:"id"`
			IsActive bool   `json:"is_active"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil || len(listResp.Data) == 0 {
		t.Fatalf("List: could not find created IOC: %v (%s)", err, w.Body.String())
	}
	id := listResp.Data[0].ID

	// ── Check finds the indicator ───────────────────────────────────────────
	if w := do(http.MethodGet, "/ioc/check?type=ip&value="+value, ""); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"match":true`)) {
		t.Fatalf("Check: expected match=true, got %d: %s", w.Code, w.Body.String())
	}

	// ── Toggle disables the indicator ───────────────────────────────────────
	w = do(http.MethodPut, "/ioc/"+id+"/toggle", `{"is_active":false}`)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"is_active":false`)) {
		t.Fatalf("Toggle: expected 200 is_active=false, got %d: %s", w.Code, w.Body.String())
	}

	// ── Delete → 200, then Check → match=false ──────────────────────────────
	if w := do(http.MethodDelete, "/ioc/"+id, ""); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/ioc/check?type=ip&value="+value, ""); !bytes.Contains(w.Body.Bytes(), []byte(`"match":false`)) {
		t.Errorf("Check after delete: expected match=false, got %s", w.Body.String())
	}
}
