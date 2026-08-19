package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ITDR (Identity Threat Detection & Response) の宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った
// インシデント・利用者・ルールを 200 で返していました（実測
// 2026-08-12）:
//
//	{"username": "admin.service", "risk_score": 9.1, "severity": "critical",
//	 "indicators": ["業務時間外の大量データアクセス", "新規デバイスからのログイン"],
//	 "detected_at": time.Now().Add(-20 * time.Minute)}
//
// **SOC の画面です。** 実在しない admin.service の侵害を追わせます。
// しかも `id` は毎回 `uuid.New()` なので、**再読み込みのたびに別の
// インシデントに見え**、「調査中」に変えることすらできません。
//
// 気づいたのは、画面が `/api/itdr/…` という**存在しない宛先**を
// 叩いていたのを直したときです。**直した先がこれでした** ——
// つまりあの書き間違いだけが、作り物を画面に出さずに済ませていました。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// 保管しているテーブルも、検知する側もありません。**作るとしたら
// ここではなく、まず ID プロバイダのログを取り込む経路です。**
type ITDRHandler struct{ pool *pgxpool.Pool }

func NewITDRHandler(pool *pgxpool.Pool) *ITDRHandler { return &ITDRHandler{pool: pool} }

// itdrUnimplemented answers every ITDR read the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。4本のうち1本でも「それらしい値」を返すと、画面はその区画だけ
// 埋まり、**残りが空なのは「まだ起きていない」からだと読まれます。**
func itdrUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "ITDR（ID脅威検知）は未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *ITDRHandler) ListIncidents(c *gin.Context) {
	itdrUnimplemented(c, "ID脅威インシデント")
}

func (h *ITDRHandler) GetTopRiskyUsers(c *gin.Context) {
	itdrUnimplemented(c, "利用者ごとのリスクスコア")
}

func (h *ITDRHandler) ListRules(c *gin.Context) {
	itdrUnimplemented(c, "ID脅威の検知ルール")
}

func (h *ITDRHandler) GetStats(c *gin.Context) {
	itdrUnimplemented(c, "ID脅威の集計")
}

// CreateRule accepted a rule and answered 201 with it.
//
// **保存していませんでした。** 作ったルールは応答の中だけに在って、
// 一覧を開き直すと消えます —— 「作った」と答えたものが次の画面に
// 無いのは、書けなかったのと同じことです。
func (h *ITDRHandler) CreateRule(c *gin.Context) {
	itdrUnimplemented(c, "ID脅威の検知ルール")
}
