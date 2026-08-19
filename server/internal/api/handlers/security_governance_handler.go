package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// セキュリティガバナンスの宛先です。
//
// **中身がありません。** ここは DB を1度も見ず、その場で作った record を
// 200 で返していました（実測 2026-08-12）:
//
//	{"title": "情報セキュリティ基本方針", "policy_number": "ISP-001",
//	 "version": "3.2", "status": "published", "owner": "CISO"}
//
// **「ISP-001 v3.2 が公開済み」は、監査で示す答えです。**
// その文書はここにありません。例外の承認記録も同じです。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// **作り物は「起きている」と読まれます** —— 3つのうち、対応や報告を
// 誤らせるのはこれだけです。
type SecurityGovernanceHandler struct{ pool *pgxpool.Pool }

func NewSecurityGovernanceHandler(pool *pgxpool.Pool) *SecurityGovernanceHandler {
	return &SecurityGovernanceHandler{pool: pool}
}

// securityGovernanceUnimplemented answers every call here the same way.
//
// **1つにまとめてあるのは、片方だけ作り物に戻せないようにするため**
// です。1本でも「それらしい値」を返すと、画面はその区画だけ埋まり、
// **残りが空なのは「まだ何も無い」からだと読まれます。**
func securityGovernanceUnimplemented(c *gin.Context, what string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "セキュリティガバナンスは未実装です。" + what +
			"を作る仕組みがサーバにありません",
		"unimplemented": true,
	})
}

func (h *SecurityGovernanceHandler) ListPolicies(c *gin.Context) {
	securityGovernanceUnimplemented(c, "ポリシー")
}

func (h *SecurityGovernanceHandler) CreatePolicy(c *gin.Context) {
	securityGovernanceUnimplemented(c, "ポリシー")
}

func (h *SecurityGovernanceHandler) UpdatePolicy(c *gin.Context) {
	securityGovernanceUnimplemented(c, "ポリシー")
}

func (h *SecurityGovernanceHandler) ListExceptions(c *gin.Context) {
	securityGovernanceUnimplemented(c, "例外申請")
}

func (h *SecurityGovernanceHandler) ApproveException(c *gin.Context) {
	securityGovernanceUnimplemented(c, "例外の承認")
}

func (h *SecurityGovernanceHandler) GetDashboard(c *gin.Context) {
	securityGovernanceUnimplemented(c, "ガバナンスの集計")
}
