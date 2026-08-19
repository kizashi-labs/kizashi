package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// コンプライアンスの自動是正の宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"name": "パスワードポリシー自動強制", "framework": "CIS",
//	 "control_id": "CIS-5.2", "remediation_type": "auto", "auto_approve": true}
//
// **「CIS-5.2 は自動で是正されている」は、監査の答えとして使われます。**
// 是正するものがありません。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type ComplianceRemediationHandler struct{ pool *pgxpool.Pool }

func NewComplianceRemediationHandler(pool *pgxpool.Pool) *ComplianceRemediationHandler {
	return &ComplianceRemediationHandler{pool: pool}
}

// complianceRemediationUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func complianceRemediationUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "コンプライアンスの自動是正は未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *ComplianceRemediationHandler) ListRules(c *gin.Context) {
	complianceRemediationUnimplemented(c, "是正ルール")
}

func (h *ComplianceRemediationHandler) CreateRule(c *gin.Context) {
	complianceRemediationUnimplemented(c, "是正ルール")
}

func (h *ComplianceRemediationHandler) ListExecutions(c *gin.Context) {
	complianceRemediationUnimplemented(c, "是正の実行履歴")
}

func (h *ComplianceRemediationHandler) ApproveExecution(c *gin.Context) {
	complianceRemediationUnimplemented(c, "是正の承認")
}

func (h *ComplianceRemediationHandler) GetDashboard(c *gin.Context) {
	complianceRemediationUnimplemented(c, "是正の集計")
}
