package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ComplianceRemediationHandler struct{ pool *pgxpool.Pool }

func NewComplianceRemediationHandler(pool *pgxpool.Pool) *ComplianceRemediationHandler {
	return &ComplianceRemediationHandler{pool: pool}
}

func (h *ComplianceRemediationHandler) ListRules(c *gin.Context) {
	rules := []gin.H{
		{"id": uuid.New(), "name": "パスワードポリシー自動強制", "framework": "CIS", "control_id": "CIS-5.2", "remediation_type": "auto", "auto_approve": true, "enabled": true, "execution_count": 47, "success_rate": 95.7},
		{"id": uuid.New(), "name": "不要アカウント無効化", "framework": "ISO27001", "control_id": "A.9.2.6", "remediation_type": "semi-auto", "auto_approve": false, "enabled": true, "execution_count": 23, "success_rate": 100.0},
		{"id": uuid.New(), "name": "未パッチシステムの隔離", "framework": "NIST", "control_id": "SI-2", "remediation_type": "semi-auto", "auto_approve": false, "enabled": true, "execution_count": 8, "success_rate": 87.5},
		{"id": uuid.New(), "name": "ファイアウォールルール検証", "framework": "PCI-DSS", "control_id": "Req-1.2", "remediation_type": "manual", "auto_approve": false, "enabled": true, "execution_count": 15, "success_rate": 93.3},
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func (h *ComplianceRemediationHandler) CreateRule(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["execution_count"] = 0
	req["success_rate"] = 0.0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *ComplianceRemediationHandler) ListExecutions(c *gin.Context) {
	executions := []gin.H{
		{"id": uuid.New(), "rule_name": "パスワードポリシー自動強制", "status": "completed", "triggered_by": "auto", "executed_at": time.Now().Add(-30 * time.Minute), "completed_at": time.Now().Add(-28 * time.Minute), "result": gin.H{"affected_users": 12, "policies_updated": 12}},
		{"id": uuid.New(), "rule_name": "不要アカウント無効化", "status": "pending", "triggered_by": "scheduler", "created_at": time.Now().Add(-5 * time.Minute)},
		{"id": uuid.New(), "rule_name": "未パッチシステムの隔離", "status": "failed", "triggered_by": "alert", "executed_at": time.Now().Add(-2 * time.Hour), "error_message": "隔離VLAN接続エラー"},
	}
	c.JSON(http.StatusOK, gin.H{"executions": executions, "total": len(executions)})
}

func (h *ComplianceRemediationHandler) ApproveExecution(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "approved", "approved_by": "admin", "approved_at": time.Now(), "message": "修復実行を承認しました"})
}

func (h *ComplianceRemediationHandler) GetDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_rules": 24, "auto_rules": 8, "semi_auto_rules": 10, "manual_rules": 6,
		"executions_today": 15, "success_today": 13, "pending_approval": 3,
		"avg_remediation_time_minutes": 12.5,
		"compliance_improvement_30d":   0.08,
		"frameworks": []gin.H{
			{"name": "CIS", "rules": 8, "compliance_rate": 0.89},
			{"name": "ISO27001", "rules": 6, "compliance_rate": 0.92},
			{"name": "NIST", "rules": 5, "compliance_rate": 0.78},
			{"name": "PCI-DSS", "rules": 5, "compliance_rate": 0.85},
		},
	})
}
