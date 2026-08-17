package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/store"
)

// testDB returns the package's shared *store.DB for integration tests
// against TEST_DATABASE_URL.
// Skips the test when the env var is unset (same gate as testPool).
//
// **共有する理由と、共有しても振る舞いが変わらない根拠は `testPool`
// の側に書いてあります。** こちらは `store.Connect` を通るので、
// `PrepareConn`（接続ごとの `app.tenant_id`）も本番と同じ形で効きます。
var (
	sharedDBOnce sync.Once
	sharedDB     *store.DB
	sharedDBErr  error
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	sharedDBOnce.Do(func() {
		sharedDB, sharedDBErr = store.Connect(context.Background(), url)
	})
	if sharedDBErr != nil {
		t.Fatalf("failed to connect to test database: %v", sharedDBErr)
	}
	return sharedDB
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

// passthroughIsolator accepts every request without touching NATS. テナント・
// ガードを見るテストに、隔離の安全弁や送出の都合を持ち込まないための stub。
type passthroughIsolator struct {
	isolated []string
}

func (p *passthroughIsolator) Isolate(_ context.Context, req isolation.Request) (isolation.Result, error) {
	p.isolated = append(p.isolated, req.AgentID)
	return isolation.Result{Outcome: isolation.OutcomeDispatched, ActionID: "row-1"}, nil
}

func (p *passthroughIsolator) Unisolate(_ context.Context, _ isolation.Request) (isolation.Result, error) {
	return isolation.Result{Outcome: isolation.OutcomeDispatched, ActionID: "row-1"}, nil
}

// TestAgentHandler_Integration_TenantGuard verifies the application-layer
// defense-in-depth tenant check on response-action endpoints (isolate/kill).
// A cross-tenant caller must get 404 BEFORE any command is dispatched, even
// though the test connects as a superuser (RLS bypassed) — proving the guard
// does not rely on RLS. Same-tenant callers proceed normally.
//
// テナントを名乗らない呼び出しは 400 です。**以前はここが 200 でした** ——
// 見出しには「single-tenant」と書いてありましたが、この検査が作る端末は
// ownerTenant のもので、単一テナント構成の話ではありませんでした。
// 本当にテナントの無い端末（tenant_id が NULL）は最後の節で見ています。
func TestAgentHandler_Integration_TenantGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	agentStore := store.NewAgentStore(db)
	h := handlers.NewAgentHandler(agentStore, nil)
	iso := &passthroughIsolator{}
	// 隔離が「通った」ことを 200 で見るには、隔離経路が結線されている必要がある。
	//
	// 以前はここを nil のままにして「Commander nil なので送出せずに 200」を
	// 通過の証拠にしていた。その 200 こそが、実行していないのに成功と報告する
	// 形そのものだったので、結線漏れは 503 で断るようにした（P5-36）。
	// このテストが見たいのはテナント・ガードなので、隔離側は素通しの stub にする。
	h.Isolator = iso

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

	// ── Cross-tenant caller → 404 (guard blocks before the gatekeeper) ────────
	if w := post(newRouter(otherTenant), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant isolate: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	// 404 を返しただけでは足りない。ガードは隔離が「実行される前に」効く必要がある。
	// 状態コードだけを見ていると、隔離してから 404 を返しても気づけない。
	if len(iso.isolated) != 0 {
		t.Errorf("クロステナントの要求が隔離まで到達した: %v", iso.isolated)
	}
	// kill-process is guarded too; the guard runs before JSON/PID validation.
	if w := post(newRouter(otherTenant), "/agents/"+id+"/kill-process", `{"pid":1234}`); w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant kill: expected 404, got %d: %s", w.Code, w.Body.String())
	}

	// ── Same-tenant caller → proceeds (200, and actually reaches the gatekeeper) ─
	if w := post(newRouter(ownerTenant), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusOK {
		t.Errorf("same-tenant isolate: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(iso.isolated) != 1 {
		t.Errorf("同一テナントの隔離が隔離経路に届いていない: %v", iso.isolated)
	}

	// ── テナントを名乗らない呼び出し → 400 ────────────────────────────────────
	//
	// **ここは 200 を期待していました。** 見出しは「Single-tenant (no
	// tenant_id) → no-op guard」でしたが、**この検査が作った端末は
	// ownerTenant のものです。** 単一テナント構成の話ではありません ——
	// 持ち主のいる端末を、名乗らない相手が操作できる、という形でした。
	//
	// 「この配備にテナントが無い」と「この呼び出し元が名乗れない」を
	// 同じ `tid == ""` で表していたのが元です。APIキー認証は構成に
	// 関係なく空を置くので、**後者だけが実際に起きます。**
	if w := post(newRouter(""), "/agents/"+id+"/isolate", `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("テナントを名乗らない隔離: expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// ── 本当にテナントの無い端末 → 素通し (200) ──────────────────────────────
	// 単一テナント構成はこちらです。行に持ち主が書かれていません。
	untenanted := uuid.NewString()
	if _, err := db.Pool().Exec(context.Background(),
		`INSERT INTO agents (id, hostname, os_type, status, source, settings, tenant_id)
		 VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb, NULL)`,
		untenanted, "untenanted-host"); err != nil {
		t.Fatalf("テナント無しの端末を作れません: %v", err)
	}
	defer func() {
		_, _ = db.Pool().Exec(context.Background(), `DELETE FROM agents WHERE id = $1`, untenanted)
	}()
	if w := post(newRouter(""), "/agents/"+untenanted+"/isolate", `{}`); w.Code != http.StatusOK {
		t.Errorf("テナントの無い端末の隔離: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
