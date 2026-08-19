package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 脅威ハンティングのキャンペーンの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "APT29 ラテラルムーブメント調査",
//	 "hypothesis": "APT29がKerberoastingを使用した横移動を実施している可能性",
//	 "tactic": "Lateral Movement"}
//
// **仮説も、その検証状況も、誰かが調べた跡として読まれます。**
// 誰も調べていません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type HuntingCampaignHandler struct{ pool *pgxpool.Pool }

func NewHuntingCampaignHandler(pool *pgxpool.Pool) *HuntingCampaignHandler {
	return &HuntingCampaignHandler{pool: pool}
}

// huntingCampaignUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func huntingCampaignUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "脅威ハンティングのキャンペーンは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *HuntingCampaignHandler) ListCampaigns(c *gin.Context) {
	huntingCampaignUnimplemented(c, "キャンペーン")
}

func (h *HuntingCampaignHandler) GetCampaign(c *gin.Context) {
	huntingCampaignUnimplemented(c, "キャンペーン")
}

func (h *HuntingCampaignHandler) CreateCampaign(c *gin.Context) {
	huntingCampaignUnimplemented(c, "キャンペーン")
}

func (h *HuntingCampaignHandler) UpdateCampaign(c *gin.Context) {
	huntingCampaignUnimplemented(c, "キャンペーン")
}

func (h *HuntingCampaignHandler) AddNote(c *gin.Context) {
	huntingCampaignUnimplemented(c, "調査メモ")
}

func (h *HuntingCampaignHandler) GetStats(c *gin.Context) {
	huntingCampaignUnimplemented(c, "ハンティングの集計")
}
