package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// テナントが分からないときに、空のリストを返さないこと。
//
// これらのハンドラは `c.GetString("tenant_id")` を
// `WHERE tenant_id = $1::uuid` にそのまま渡します。空文字は uuid として
// 解釈できないので、そのリクエストは1件も読めません。
//
// **空になる経路は実在します。** router.go はAPIキー認証で
// `c.Set("tenant_id", "")` を無条件に置くので、**SDK からの読み取りは
// 全部これです。** tenant_id クレームの無い JWT（単一テナント構成、
// 組み込みの admin）も同じです。
//
// 直前までの姿:
//
//	rows, err := h.pool.Query(...)   // ここは通る
//	for rows.Next() { ... }          // 1周も回らない
//	c.JSON(200, out)                 // 空のリスト
//
// クエリの失敗は `rows.Err()` にしか出ないので、**200 と `[]` が返って
// いました。**「カオス実験は0件です」と読める応答です。同じキャンペーンで
// rows.Err() を足したところ、隠れていた失敗が 500 として出てきました ——
// このテストの6本が緑だったのは、握り潰された失敗に 200 を期待して
// いたからです。
//
// 500 でも呼び出し側は何をすればよいか分かりません。400 で理由を書きます。

func callList(t *testing.T, tenant string, h gin.HandlerFunc) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/list", nil)
	c.Set("user_id", stubUserID)
	if tenant != "" {
		c.Set("tenant_id", tenant)
	}
	h(c)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func TestListWithoutATenantIsNotAnEmptyList(t *testing.T) {
	pool := testPool(t)

	for _, c := range []struct {
		name string
		h    gin.HandlerFunc
	}{
		{"chaos/experiments", handlers.NewChaosHandler(pool).ListExperiments},
		{"chaos/runs", handlers.NewChaosHandler(pool).ListRuns},
		{"chaos/approvals", handlers.NewChaosHandler(pool).ListApprovals},
		{"phishing/templates", handlers.NewPhishingHandler(pool).ListTemplates},
		{"phishing/campaigns", handlers.NewPhishingHandler(pool).ListCampaigns},
		{"pentest/engagements", handlers.NewPentestHandler(pool).ListEngagements},
		{"pentest/findings", handlers.NewPentestHandler(pool).ListFindings},
		{"drills", handlers.NewIncidentDrillsHandler(pool).List},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body := callList(t, "", c.h)

			if code == http.StatusOK {
				t.Fatalf("テナントが分からないのに 200 を返しています。"+
					"呼び出し側には「0件」と読めます: %v", body)
			}
			if code >= 500 {
				t.Fatalf("500 を返しています。答えられない理由はこちら側に"+
					"あるので、呼び出し側は再試行しかできません: %d %v", code, body)
			}
			if code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", code)
			}
			if body["tenant_missing"] != true {
				t.Errorf("理由が応答に載っていません: %v", body)
			}
		})
	}
}

// テナントが分かるときは、これまで通り読めること。
// 断る側だけ直して、通る側を塞いでいないことを確かめます。
func TestListWithATenantStillReads(t *testing.T) {
	pool := testPool(t)

	for _, c := range []struct {
		name string
		h    gin.HandlerFunc
	}{
		{"chaos/experiments", handlers.NewChaosHandler(pool).ListExperiments},
		{"phishing/templates", handlers.NewPhishingHandler(pool).ListTemplates},
		{"pentest/engagements", handlers.NewPentestHandler(pool).ListEngagements},
		{"drills", handlers.NewIncidentDrillsHandler(pool).List},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body := callList(t, stubTenantID, c.h)
			if code != http.StatusOK {
				t.Errorf("status = %d, want 200 (body: %v)", code, body)
			}
		})
	}
}
