package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/store"
)

// SystemAccessMiddleware marks a route as needing all-tenant database access.
//
// **認証前の経路にだけ張ります。** ログイン・ハートビート・端末の登録・
// 取り込みは、テナントが決まる前に走ります（鶏と卵）。テナントを絞れない
// ので、いまは RLS のエスケープ節（`app.tenant_id` が未設定なら全行）が
// これらを通しています。
//
// **エスケープ節は「設定し忘れた接続」も同じように通します。** 名乗りに
// 変えると、忘れた接続は（抜け道を落としたあと）0 行になり、全テナントを
// 見るのは名乗った経路だけになります。
//
// 張った経路は internal/api/system_access_ledger_test.go が名前で留めます。
// **増やすときは理由を書いてください。** 張れる場所が増えるほど、
// 「名乗り」は「既定」に戻ります。
//
// `TenantMiddleware` と併用しないこと。両方立つと
// `store.prepareConnForTenant` が落とします（どちらの意図か決まらないので、
// 黙って片方を選ばせません）。
func SystemAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request = c.Request.WithContext(store.WithSystemAccess(c.Request.Context()))
		c.Next()
	}
}
