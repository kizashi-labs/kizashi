package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ワークフローのオーケストレーションの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "アラート自動トリアージ", "execution_count": 234,
//	 "success_count": 229, "failure_count": 5}
//
// **「234回実行して 229 成功」は、成功率として読まれます。**
// 1回も実行されていません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type OrchestrationEnhancedHandler struct{ pool *pgxpool.Pool }

func NewOrchestrationEnhancedHandler(pool *pgxpool.Pool) *OrchestrationEnhancedHandler {
	return &OrchestrationEnhancedHandler{pool: pool}
}

// orchestrationEnhancedUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func orchestrationEnhancedUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "ワークフローのオーケストレーションは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *OrchestrationEnhancedHandler) ListWorkflows(c *gin.Context) {
	orchestrationEnhancedUnimplemented(c, "ワークフロー")
}

func (h *OrchestrationEnhancedHandler) ExecuteWorkflow(c *gin.Context) {
	orchestrationEnhancedUnimplemented(c, "ワークフローの実行")
}

func (h *OrchestrationEnhancedHandler) GetExecution(c *gin.Context) {
	orchestrationEnhancedUnimplemented(c, "実行結果")
}

func (h *OrchestrationEnhancedHandler) GetStats(c *gin.Context) {
	orchestrationEnhancedUnimplemented(c, "実行の集計")
}
