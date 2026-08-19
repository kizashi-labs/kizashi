package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// セキュリティ診断の宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "2024年度 ISO27001 ギャップ分析", "framework": "ISO27001",
//	 "status": "completed", "assessor": "外部監査法人A"}
//
// **「外部監査法人Aによる診断が完了している」は、監査の答えとして
// 使われます。** その診断はありません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type SecurityAssessmentHandler struct{ pool *pgxpool.Pool }

func NewSecurityAssessmentHandler(pool *pgxpool.Pool) *SecurityAssessmentHandler {
	return &SecurityAssessmentHandler{pool: pool}
}

// securityAssessmentUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func securityAssessmentUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "セキュリティ診断は未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *SecurityAssessmentHandler) ListAssessments(c *gin.Context) {
	securityAssessmentUnimplemented(c, "診断")
}

func (h *SecurityAssessmentHandler) GetAssessment(c *gin.Context) {
	securityAssessmentUnimplemented(c, "診断")
}

func (h *SecurityAssessmentHandler) CreateAssessment(c *gin.Context) {
	securityAssessmentUnimplemented(c, "診断")
}

func (h *SecurityAssessmentHandler) UpdateAssessment(c *gin.Context) {
	securityAssessmentUnimplemented(c, "診断")
}

func (h *SecurityAssessmentHandler) GetStats(c *gin.Context) {
	securityAssessmentUnimplemented(c, "診断の集計")
}
