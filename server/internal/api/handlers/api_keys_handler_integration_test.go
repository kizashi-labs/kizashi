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

// TestAPIKeyHandler_Integration_Lifecycle exercises Create/List/Revoke against a
// real (migrated) database: create a key, list it, revoke it, confirm revoked.
func TestAPIKeyHandler_Integration_Lifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	h := handlers.NewAPIKeyHandler(store.NewAPIKeyStore(pool))

	const userID = "d4d4d4d4-e5e5-f6f6-a7a7-b8b8b8b8b8b8"
	const keyName = "itest-key"
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM api_keys WHERE user_id=$1", userID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id=$1", userID)
	}
	cleanup()
	t.Cleanup(cleanup)

	// api_keys.user_id has a FK to users — seed the owning user first.
	if _, err := pool.Exec(ctx,
		"INSERT INTO users (id, email) VALUES ($1, $2)", userID, "itest-apikey@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := gin.New()
	// Inject an authenticated user, as the auth middleware would.
	r.Use(func(c *gin.Context) { c.Set("user_id", userID) })
	r.POST("/api-keys", h.Create)
	r.GET("/api-keys", h.List)
	r.DELETE("/api-keys/:id", h.Revoke)

	doJSON := func(method, target string, body any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, target, rdr)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create (valid) returns a one-time raw key ───────────────────────────
	w := doJSON(http.MethodPost, "/api-keys", map[string]any{"name": keyName, "scopes": []string{"read", "write"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if key, _ := created["key"].(string); key == "" {
		t.Errorf("Create: expected a non-empty raw key, got %v", created)
	}

	// ── Create (invalid scope) → 400 ────────────────────────────────────────
	if w := doJSON(http.MethodPost, "/api-keys", map[string]any{"name": "bad", "scopes": []string{"superadmin"}}); w.Code != http.StatusBadRequest {
		t.Errorf("Create(invalid scope): expected 400, got %d", w.Code)
	}

	// ── List includes the created key (not revoked) ─────────────────────────
	id := findKeyID(t, doJSON(http.MethodGet, "/api-keys", nil), keyName)
	if id == "" {
		t.Fatal("List: created key not found")
	}

	// ── Revoke it ───────────────────────────────────────────────────────────
	if w := doJSON(http.MethodDelete, "/api-keys/"+id, nil); w.Code != http.StatusOK {
		t.Fatalf("Revoke: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── List now shows it as revoked ────────────────────────────────────────
	list := decodeKeys(t, doJSON(http.MethodGet, "/api-keys", nil))
	found := false
	for _, k := range list {
		if k["id"] == id {
			found = true
			if revoked, _ := k["revoked"].(bool); !revoked {
				t.Errorf("key should be revoked after Revoke: %+v", k)
			}
		}
	}
	if !found {
		t.Error("revoked key should still be listed (with revoked=true)")
	}
}

func decodeKeys(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	var body struct {
		APIKeys []map[string]any `json:"api_keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("List: invalid JSON: %v", err)
	}
	return body.APIKeys
}

func findKeyID(t *testing.T, w *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, k := range decodeKeys(t, w) {
		if k["name"] == name {
			id, _ := k["id"].(string)
			if revoked, _ := k["revoked"].(bool); revoked {
				t.Errorf("freshly created key should not be revoked: %+v", k)
			}
			return id
		}
	}
	return ""
}
