package middleware

import (
	"net/http"

	"github.com/edr-platform/server/internal/license"
	"github.com/gin-gonic/gin"
)

// このファイルはオープンソース版のスタブです。
//
// 商用版では、ライセンスのプラン階層に応じて機能へのアクセスを制限します。
// オープンソース版にはプランが存在せず、このリポジトリに含まれる機能はすべて
// 利用できます。呼び出し側を書き換えずに済むよう、同じ API を保ったまま
// 常に通過させます。
//
// This is the open source edition stub. There are no plans and no feature
// gating here; every check passes. See internal/license for the rationale.

// EnforceAgentLimit is a no-op in this edition: there is no agent limit.
func EnforceAgentLimit(_ *license.Manager) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// RequireFeature is a no-op in this edition: every feature that ships in this
// repository is available. Features that are absent are absent entirely —
// their routes are not registered, so they never reach this middleware.
func RequireFeature(_ *license.Manager, _ string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// RequireAIOptIn still enforces explicit operator consent before any data may
// be sent to an external AI provider. This is a privacy boundary, not a
// licensing one, so it is kept rather than stubbed out.
//
// 背景: 個人情報保護法の第三者提供・越境移転の規律。アラート本文には
// ホスト名・パス・利用者情報が含まれ得るため、外部 API への送信は
// 管理者の明示的な同意なしに行わない。
func RequireAIOptIn(mgr *license.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if mgr == nil || !mgr.HasAIExternalOptin() {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "ai_optin_required",
				"message": "外部 AI API へのデータ送信には管理者の同意が必要です。",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
