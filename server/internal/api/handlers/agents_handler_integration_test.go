package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// testDB opens a *store.DB for integration tests against TEST_DATABASE_URL.
// Skips the test when the env var is unset (same gate as testPool).
func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestAgentHandler_Integration_CRUD exercises the agent List/Get/Delete handlers
// end-to-end against a real (migrated) database via the store layer.
func TestAgentHandler_Integration_CRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	agentStore := store.NewAgentStore(db)
	h := handlers.NewAgentHandler(agentStore, nil) // Commander unused on read/delete paths

	const id = "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5"
	const hostname = "itest-agent-crud"
	ctx := context.Background()

	// Ensure a clean slate and clean up afterwards.
	cleanup := func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", id) }
	cleanup()
	t.Cleanup(cleanup)

	if err := agentStore.UpsertAgent(ctx, &store.AgentRow{
		ID:           id,
		Hostname:     hostname,
		OSType:       "linux",
		OSVersion:    "Ubuntu 22.04",
		AgentVersion: "1.0.0",
		IPAddresses:  []string{"10.0.0.5"},
		Status:       "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	r := gin.New()
	r.GET("/agents", h.List)
	r.GET("/agents/:id", h.Get)
	r.DELETE("/agents/:id", h.Delete)

	do := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, target, nil))
		return w
	}

	// ── Get returns the upserted agent ──────────────────────────────────────
	w := do(http.MethodGet, "/agents/"+id)
	if w.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("Get: invalid JSON: %v", err)
	}
	if got["id"] != id || got["hostname"] != hostname {
		t.Errorf("Get: unexpected agent payload: %+v", got)
	}

	// ── List (filtered by our unique hostname) includes the agent ───────────
	w = do(http.MethodGet, "/agents?search="+hostname)
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	var list struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("List: invalid JSON: %v", err)
	}
	found := false
	for _, a := range list.Data {
		if a["id"] == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("List: upserted agent %s not found in results (total=%d)", id, list.Total)
	}

	// ── Get on a non-existent id → 404 ──────────────────────────────────────
	if w := do(http.MethodGet, "/agents/00000000-0000-0000-0000-000000000000"); w.Code != http.StatusNotFound {
		t.Errorf("Get(nonexistent): expected 404, got %d", w.Code)
	}

	// ── Delete removes the agent, then Get → 404 ────────────────────────────
	if w := do(http.MethodDelete, "/agents/"+id); w.Code != http.StatusOK {
		t.Errorf("Delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/agents/"+id); w.Code != http.StatusNotFound {
		t.Errorf("Get after delete: expected 404, got %d", w.Code)
	}
}

// TestAgentHandler_Integration_ListShape checks the List response envelope
// (data/total/page/per_page) against a real DB.
func TestAgentHandler_Integration_ListShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	h := handlers.NewAgentHandler(store.NewAgentStore(db), nil)

	r := gin.New()
	r.GET("/agents", h.List)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agents?page=1&per_page=5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"data", "total", "page", "per_page", "has_more"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("List response missing %q key: %+v", key, resp)
		}
	}
}

// TestAgentHandler_Integration_ProtectionSummary checks that a reported
// protection_mode is aggregated by the protection-summary endpoint.
func TestAgentHandler_Integration_ProtectionSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	agentStore := store.NewAgentStore(db)
	h := handlers.NewAgentHandler(agentStore, nil)

	const id = "a2a2a2a2-b2b2-c3c3-d4d4-e5e5e5e5e5e5"
	ctx := context.Background()
	cleanup := func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", id) }
	cleanup()
	t.Cleanup(cleanup)

	if err := agentStore.UpsertAgent(ctx, &store.AgentRow{
		ID: id, Hostname: "itest-protection", OSType: "linux", Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := agentStore.UpdateProtectionMode(ctx, id, "enforce"); err != nil {
		t.Fatalf("UpdateProtectionMode: %v", err)
	}

	r := gin.New()
	r.GET("/agents-protection-summary", h.ProtectionSummary)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agents-protection-summary", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ProtectionSummary: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		ByMode          map[string]int `json:"by_mode"`
		Total           int            `json:"total"`
		EnforceReadyPct int            `json:"enforce_ready_pct"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.ByMode["enforce"] < 1 {
		t.Errorf("expected enforce >= 1 after reporting, got by_mode=%v", resp.ByMode)
	}
	if resp.Total < 1 {
		t.Errorf("expected total >= 1, got %d", resp.Total)
	}
}

// TestAgentHandler_Integration_TenantGuard verifies the application-layer
// defense-in-depth tenant check on response-action endpoints (isolate/kill).
// A cross-tenant caller must get 404 BEFORE any command is dispatched, even
// though the test connects as a superuser (RLS bypassed) — proving the guard
// does not rely on RLS. Same-tenant and single-tenant (no tenant_id) callers
// proceed normally.
func TestAgentHandler_Integration_TenantGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	agentStore := store.NewAgentStore(db)
	// Commander nil: the same-tenant path returns 200 without dispatching a real
	// command, which is exactly what we want to assert the guard let it through.
	h := handlers.NewAgentHandler(agentStore, nil)

	const id = "b2b2b2b2-c3c3-d4d4-e5e5-f6f6f6f6f6f6"
	const ownerTenant = "00000000-0000-0000-0000-000000000001" // default tenant (exists → satisfies FK)
	const otherTenant = "99999999-9999-9999-9999-999999999999"
	ctx := context.Background()

	cleanup := func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", id) }
	cleanup()
	t.Cleanup(cleanup)

	if err := agentStore.UpsertAgent(ctx, &store.AgentRow{
		ID: id, Hostname: "itest-tenant-guard", OSType: "linux",
		AgentVersion: "1.0.0", Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, "UPDATE agents SET tenant_id=$2 WHERE id=$1", id, ownerTenant); err != nil {
		t.Fatalf("set tenant_id: %v", err)
	}

	// Router with a middleware that injects a per-request tenant_id, mimicking
	// the auth/tenant middleware that normally sets it from the JWT.
	newRouter := func(tenant string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if tenant != "" {
				c.Set("tenant_id", tenant)
			}
			c.Next()
		})
		r.POST("/agents/:id/isolate", h.Isolate)
		r.POST("/agents/:id/kill-process", h.KillProcess)
		return r
	}
	post := func(r *gin.Engine, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// ── Cross-tenant caller → 404 (guard blocks before any dispatch) ──────────
	if w := post(newRouter(otherTenant), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant isolate: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	// kill-process is guarded too; the guard runs before JSON/PID validation.
	if w := post(newRouter(otherTenant), "/agents/"+id+"/kill-process", `{"pid":1234}`); w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant kill: expected 404, got %d: %s", w.Code, w.Body.String())
	}

	// ── Same-tenant caller → proceeds (200; Commander nil so no dispatch) ─────
	if w := post(newRouter(ownerTenant), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusOK {
		t.Errorf("same-tenant isolate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Single-tenant (no tenant_id) → no-op guard, proceeds (200) ────────────
	if w := post(newRouter(""), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusOK {
		t.Errorf("single-tenant isolate: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
