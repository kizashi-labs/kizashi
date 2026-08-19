package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// セキュリティデータウェアハウスの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "アラートデータセット", "source_type": "alerts_db",
//	 "status": "active", "row_count": 2847391, "size_bytes": 1.2e9}
//
// **284万行のデータセットは存在しません。** `ExecuteQuery` は問い合わせを
// 受け取って結果を作り、`GetQueryResult` はその結果を作り直します ——
// **同じクエリが毎回違う答えを返します。**
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type SecurityDWHandler struct{ pool *pgxpool.Pool }

func NewSecurityDWHandler(pool *pgxpool.Pool) *SecurityDWHandler {
	return &SecurityDWHandler{pool: pool}
}

// securityDWUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func securityDWUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "セキュリティデータウェアハウスは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *SecurityDWHandler) ListDatasets(c *gin.Context) {
	securityDWUnimplemented(c, "データセット")
}

func (h *SecurityDWHandler) ExecuteQuery(c *gin.Context) {
	securityDWUnimplemented(c, "クエリの実行")
}

func (h *SecurityDWHandler) GetQueryResult(c *gin.Context) {
	securityDWUnimplemented(c, "クエリ結果")
}

func (h *SecurityDWHandler) GetStats(c *gin.Context) {
	securityDWUnimplemented(c, "データセットの集計")
}
