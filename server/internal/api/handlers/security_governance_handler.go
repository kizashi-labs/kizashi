package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityGovernanceHandler struct{ pool *pgxpool.Pool }

func NewSecurityGovernanceHandler(pool *pgxpool.Pool) *SecurityGovernanceHandler {
	return &SecurityGovernanceHandler{pool: pool}
}

func (h *SecurityGovernanceHandler) ListPolicies(c *gin.Context) {
	policies := []gin.H{
		{"id": uuid.New(), "title": "情報セキュリティ基本方針", "policy_number": "ISP-001", "category": "governance", "version": "3.2", "status": "published", "owner": "CISO", "effective_date": "2024-01-01", "review_date": "2025-01-01", "frameworks": []string{"ISO27001", "NIST"}, "acknowledged_count": 145, "total_staff": 150},
		{"id": uuid.New(), "title": "アクセス制御ポリシー", "policy_number": "ACP-002", "category": "access_control", "version": "2.1", "status": "published", "owner": "IT部門長", "effective_date": "2024-02-01", "review_date": "2025-02-01", "frameworks": []string{"ISO27001", "PCI-DSS"}, "acknowledged_count": 142, "total_staff": 150},
		{"id": uuid.New(), "title": "インシデント対応手順書", "policy_number": "IRP-003", "category": "incident_response", "version": "1.8", "status": "review", "owner": "SOC Manager", "effective_date": "2023-06-01", "review_date": "2024-06-01", "frameworks": []string{"NIST", "ISO27001"}, "acknowledged_count": 0, "total_staff": 150},
		{"id": uuid.New(), "title": "データ分類ポリシー", "policy_number": "DCP-004", "category": "data_management", "version": "1.5", "status": "draft", "owner": "DPO", "frameworks": []string{"GDPR", "ISO27001"}, "acknowledged_count": 0, "total_staff": 150},
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

func (h *SecurityGovernanceHandler) CreatePolicy(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["version"] = "1.0"
	req["status"] = "draft"
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *SecurityGovernanceHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = id
	req["updated_at"] = time.Now()
	c.JSON(http.StatusOK, req)
}

func (h *SecurityGovernanceHandler) ListExceptions(c *gin.Context) {
	exceptions := []gin.H{
		{"id": uuid.New(), "title": "レガシーシステム暗号化除外申請", "risk_level": "high", "status": "approved", "requestor": "インフラ部門", "approver": "CISO", "valid_until": time.Now().Add(90 * 24 * time.Hour).Format("2006-01-02"), "justification": "2024年度末に移行予定のため一時的除外を申請"},
		{"id": uuid.New(), "title": "開発環境MFA除外", "risk_level": "medium", "status": "pending", "requestor": "開発部門", "justification": "CI/CDパイプラインの自動化のため非対話型アカウントのMFA除外を申請"},
	}
	c.JSON(http.StatusOK, gin.H{"exceptions": exceptions, "total": len(exceptions)})
}

func (h *SecurityGovernanceHandler) ApproveException(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "approved", "approved_by": "CISO", "approved_at": time.Now()})
}

func (h *SecurityGovernanceHandler) GetDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_policies": 24, "published": 18, "review": 4, "draft": 2,
		"acknowledgment_rate": 0.947,
		"overdue_reviews":     3, "upcoming_reviews_30d": 5,
		"exceptions": gin.H{"total": 8, "pending": 2, "approved": 5, "expired": 1},
		"frameworks_coverage": []gin.H{
			{"framework": "ISO27001", "policies": 18, "coverage": 0.92},
			{"framework": "NIST", "policies": 12, "coverage": 0.78},
			{"framework": "PCI-DSS", "policies": 8, "coverage": 0.85},
			{"framework": "GDPR", "policies": 10, "coverage": 0.88},
		},
	})
}
