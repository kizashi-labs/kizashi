package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 自動化トリガーの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "クリティカルアラート自動対応", "trigger_type": "alert",
//	 "enabled": true, "fire_count": 47, "last_fired_at": time.Now().Add(-…)}
//
// **「47回発火した、最後は数分前」は、自動対応が動いている証拠として
// 読まれます。** 動いていません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type AutomationEnhancedHandler struct{ pool *pgxpool.Pool }

func NewAutomationEnhancedHandler(pool *pgxpool.Pool) *AutomationEnhancedHandler {
	return &AutomationEnhancedHandler{pool: pool}
}

// automationEnhancedUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func automationEnhancedUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "自動化トリガーは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *AutomationEnhancedHandler) ListTriggers(c *gin.Context) {
	automationEnhancedUnimplemented(c, "トリガー")
}

func (h *AutomationEnhancedHandler) CreateTrigger(c *gin.Context) {
	automationEnhancedUnimplemented(c, "トリガー")
}

func (h *AutomationEnhancedHandler) ListRuns(c *gin.Context) {
	automationEnhancedUnimplemented(c, "実行履歴")
}

func (h *AutomationEnhancedHandler) GetStats(c *gin.Context) {
	automationEnhancedUnimplemented(c, "自動化の集計")
}
