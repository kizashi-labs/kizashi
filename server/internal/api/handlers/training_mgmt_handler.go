package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// セキュリティ研修の管理の宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "セキュリティ基礎研修", "program_type": "awareness",
//	 "duration_hours": 4.0, "passing_score": 80, "certification_valid_days": 365}
//
// **受講状況は、コンプライアンスの証跡として提出されます。**
// 受講記録はありません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type TrainingMgmtHandler struct{ pool *pgxpool.Pool }

func NewTrainingMgmtHandler(pool *pgxpool.Pool) *TrainingMgmtHandler {
	return &TrainingMgmtHandler{pool: pool}
}

// trainingMgmtUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func trainingMgmtUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "セキュリティ研修の管理は未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *TrainingMgmtHandler) ListPrograms(c *gin.Context) {
	trainingMgmtUnimplemented(c, "研修プログラム")
}

func (h *TrainingMgmtHandler) CreateProgram(c *gin.Context) {
	trainingMgmtUnimplemented(c, "研修プログラム")
}

func (h *TrainingMgmtHandler) ListEnrollments(c *gin.Context) {
	trainingMgmtUnimplemented(c, "受講状況")
}

func (h *TrainingMgmtHandler) EnrollUser(c *gin.Context) {
	trainingMgmtUnimplemented(c, "受講登録")
}

func (h *TrainingMgmtHandler) GetStats(c *gin.Context) {
	trainingMgmtUnimplemented(c, "研修の集計")
}
