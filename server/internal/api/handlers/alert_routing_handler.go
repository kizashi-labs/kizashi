package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// アラートのルーティングの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "クリティカルアラート → PagerDuty", "priority": 10,
//	 "match_count": 234, "destinations": ["PagerDuty", "Slack #incidents"]}
//
// **「234件がこのルートで流れた」は、通知が効いている証拠として
// 読まれます。** 実際には1件も流れていません —— このルートは存在せず、
// PagerDuty にも Slack にも何も送られていません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type AlertRoutingHandler struct{ pool *pgxpool.Pool }

func NewAlertRoutingHandler(pool *pgxpool.Pool) *AlertRoutingHandler {
	return &AlertRoutingHandler{pool: pool}
}

// alertRoutingUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func alertRoutingUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "アラートのルーティングは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *AlertRoutingHandler) ListRules(c *gin.Context) {
	alertRoutingUnimplemented(c, "ルート")
}

func (h *AlertRoutingHandler) CreateRule(c *gin.Context) {
	alertRoutingUnimplemented(c, "ルート")
}

func (h *AlertRoutingHandler) UpdateRule(c *gin.Context) {
	alertRoutingUnimplemented(c, "ルート")
}

func (h *AlertRoutingHandler) DeleteRule(c *gin.Context) {
	alertRoutingUnimplemented(c, "ルート")
}

func (h *AlertRoutingHandler) ListDestinations(c *gin.Context) {
	alertRoutingUnimplemented(c, "通知先")
}

func (h *AlertRoutingHandler) CreateDestination(c *gin.Context) {
	alertRoutingUnimplemented(c, "通知先")
}

func (h *AlertRoutingHandler) TestDestination(c *gin.Context) {
	alertRoutingUnimplemented(c, "通知先への試験送信")
}

func (h *AlertRoutingHandler) GetStats(c *gin.Context) {
	alertRoutingUnimplemented(c, "ルーティングの集計")
}
