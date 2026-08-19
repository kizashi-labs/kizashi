package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// テナントが分からないリクエストが、他テナントの端末を隔離できないこと。
//
// `ensureAgentInTenant` は「テナントが空なら単一テナント構成」と読んで
// **そのまま通します**（`if tid == "" { return true }`）。コメントにも
// 「In single-tenant mode (no tenant_id) it is a no-op」と書いてあります。
//
// **その前提は、APIキーでは成り立ちません。** `router.go` は
// APIキー認証で無条件に `c.Set("tenant_id", "")` を置きます。構成が
// 単一テナントかどうかとは無関係です。ログインは必ずテナントを載せる
// ので（既定値に倒してでも）、**空になるのは実質APIキーだけです。**
//
// 下の層も止めません:
//
//   - `AgentBelongsToTenant` はそもそも呼ばれません
//   - RLS の方針は `current_setting('app.tenant_id') = ''` を
//     **全テナント可**として扱います。`TenantMiddleware` は空のときに
//     ctx へ入れないので、`app.tenant_id` は設定されないままです
//
// この関数のコメント自身が「RLS が効いていない場合でも cross-tenant BOLA を
// 塞ぐため」と書いています。**塞ぐはずの経路が、いちばん通り抜けます。**
//
// 端末の隔離は、通信を落とす操作です。

func agentGuardCtx(t *testing.T, tenant, agentID string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost,
		"/api/v1/agents/"+agentID+"/isolate", strings.NewReader(`{"reason":"test"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: agentID}}
	c.Set("user_id", stubUserID)
	if tenant != "" {
		c.Set("tenant_id", tenant)
	}
	return c, w
}

func TestIsolateWithoutATenantCannotReachAnotherTenantsAgent(t *testing.T) {
	db := testDB(t)
	pool := db.Pool()
	ctx := context.Background()

	victimTenant := uuid.NewString()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		victimTenant, "victim "+victimTenant[:8], "v-"+victimTenant[:8]); err != nil {
		t.Fatalf("テナントを作れません: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id, hostname, os_type, status, source, settings, tenant_id)
		 VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb, $3)`,
		agentID, "victim-host", victimTenant); err != nil {
		t.Fatalf("エージェントを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, victimTenant)
	})

	h := handlers.NewAgentHandler(store.NewAgentStore(db), nil)
	// 結線漏れは 503 で断る（#757 / P5-36）。この検査が見たいのはテナント・
	// ガードなので、隔離側は素通しの stub にする。
	h.Isolator = &passthroughIsolator{}

	// テナントの分からないリクエスト —— APIキー認証がこの形です。
	c, w := agentGuardCtx(t, "", agentID)
	h.Isolate(c)

	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	if w.Code == http.StatusOK {
		t.Errorf("テナントの分からないリクエストが、他テナントの端末を隔離しました "+
			"(status %d, %v)。APIキーは常にこの形で届きます", w.Code, body)
	}

	// 何より、実際に隔離されていないこと。応答だけ直しても意味がありません。
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM agents WHERE id = $1`, agentID).Scan(&status); err != nil {
		t.Fatalf("状態を読めません: %v", err)
	}
	if status == "isolated" {
		t.Error("他テナントの端末が実際に隔離されています。通信が落ちています")
	}
}

// 自分のテナントの端末は、これまで通り隔離できること。
// 塞ぐ側だけ直して、正規の対応操作を止めていないことを確かめます。
func TestIsolateWithinYourOwnTenantStillWorks(t *testing.T) {
	db := testDB(t)
	pool := db.Pool()
	ctx := context.Background()

	tenant := uuid.NewString()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenant, "own "+tenant[:8], "o-"+tenant[:8]); err != nil {
		t.Fatalf("テナントを作れません: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id, hostname, os_type, status, source, settings, tenant_id)
		 VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb, $3)`,
		agentID, "own-host", tenant); err != nil {
		t.Fatalf("エージェントを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
	})

	h := handlers.NewAgentHandler(store.NewAgentStore(db), nil)
	// 結線漏れは 503 で断る（#757 / P5-36）。この検査が見たいのはテナント・
	// ガードなので、隔離側は素通しの stub にする。
	h.Isolator = &passthroughIsolator{}
	c, w := agentGuardCtx(t, tenant, agentID)
	h.Isolate(c)

	if w.Code != http.StatusOK {
		t.Fatalf("自分のテナントの端末を隔離できません: %d %s", w.Code, w.Body.String())
	}
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM agents WHERE id = $1`, agentID).Scan(&status); err != nil {
		t.Fatalf("状態を読めません: %v", err)
	}
	if status != "isolated" {
		t.Errorf("status = %q, want isolated", status)
	}
}
