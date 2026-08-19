package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DRP（デジタルリスク保護 / ダークウェブ監視）の宛先です。
//
// **中身がありません。** ここは DB も外部の購読も1度も見ず、その場で
// 作った監視と検出を 200 で返していました（実測 2026-08-12）:
//
//	{"title": "企業メールアドレスがダークウェブデータベースで発見",
//	 "source": "darkweb_forum", "severity": "critical",
//	 "status": "investigating", "found_at": time.Now().Add(-2 * time.Hour)}
//
//	{"title": "GitHubにハードコードされた認証情報を発見",
//	 "source": "github", "severity": "critical", "status": "mitigated"}
//
// **「2時間前に認証情報の漏洩を検出、調査中」は、対応を始めさせる形**
// です。漏れていない認証情報の失効作業が走ります。しかも
// `status: "investigating"` は、**誰かが既に見ていることまで**
// 示しています。
//
// `CreateMonitor` は受け取った JSON に `id` を足して 201 を返し、
// `UpdateFinding` は受け取った JSON に `updated_at` を足して 200 を
// 返します —— **どちらも保存しません。** 作った監視は次の画面に
// ありません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// 作るとしたら、まず購読する情報源（漏洩データベース、フォーラム、
// ドメイン登録）を決めるところからです。
type DRPHandler struct{ pool *pgxpool.Pool }

func NewDRPHandler(pool *pgxpool.Pool) *DRPHandler { return &DRPHandler{pool: pool} }

// drpUnimplemented answers every DRP call the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。
func drpUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "DRP（デジタルリスク保護）は未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *DRPHandler) ListMonitors(c *gin.Context) {
	drpUnimplemented(c, "監視の一覧")
}

// CreateMonitor echoed the request back with an id and stored nothing.
func (h *DRPHandler) CreateMonitor(c *gin.Context) {
	drpUnimplemented(c, "監視の登録")
}

func (h *DRPHandler) ListFindings(c *gin.Context) {
	drpUnimplemented(c, "漏洩・詐称の検出")
}

// UpdateFinding echoed the request back with a timestamp and stored nothing.
func (h *DRPHandler) UpdateFinding(c *gin.Context) {
	drpUnimplemented(c, "検出の状態")
}

func (h *DRPHandler) GetStats(c *gin.Context) {
	drpUnimplemented(c, "検出の集計")
}
