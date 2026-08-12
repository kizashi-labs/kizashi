package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CSPMEnhancedHandler struct{ pool *pgxpool.Pool }

func NewCSPMEnhancedHandler(pool *pgxpool.Pool) *CSPMEnhancedHandler {
	return &CSPMEnhancedHandler{pool: pool}
}

func (h *CSPMEnhancedHandler) ListAccounts(c *gin.Context) {
	accounts := []gin.H{
		{"id": uuid.New(), "cloud_provider": "aws", "account_id": "123456789012", "account_name": "Production Account", "posture_score": 7.8, "critical_findings": 3, "high_findings": 12, "scan_status": "completed", "last_scanned_at": time.Now().Add(-1 * time.Hour), "enabled": true},
		{"id": uuid.New(), "cloud_provider": "azure", "account_id": "sub-abc123", "account_name": "Azure Production", "posture_score": 8.2, "critical_findings": 1, "high_findings": 8, "scan_status": "completed", "last_scanned_at": time.Now().Add(-2 * time.Hour), "enabled": true},
		{"id": uuid.New(), "cloud_provider": "gcp", "account_id": "project-xyz", "account_name": "GCP Project", "posture_score": 6.9, "critical_findings": 5, "high_findings": 18, "scan_status": "scanning", "last_scanned_at": time.Now().Add(-30 * time.Minute), "enabled": true},
	}
	c.JSON(http.StatusOK, gin.H{"accounts": accounts, "total": len(accounts)})
}

func (h *CSPMEnhancedHandler) ListFindings(c *gin.Context) {
	findings := []gin.H{
		{"id": uuid.New(), "resource_type": "S3_Bucket", "resource_id": "prod-data-bucket", "region": "ap-northeast-1", "check_id": "S3-001", "check_name": "S3バケット公開アクセス", "severity": "critical", "status": "open", "description": "S3バケットがパブリックアクセスを許可しています", "remediation": "バケットポリシーでPublicAccessBlockを有効化してください", "compliance_frameworks": []string{"CIS", "PCI-DSS"}},
		{"id": uuid.New(), "resource_type": "IAM_Role", "resource_id": "admin-role", "region": "global", "check_id": "IAM-001", "check_name": "IAMロール過剰権限", "severity": "high", "status": "open", "description": "管理者権限のIAMロールがMFAなしで使用可能", "remediation": "MFA条件をIAMポリシーに追加してください", "compliance_frameworks": []string{"CIS", "NIST"}},
		{"id": uuid.New(), "resource_type": "Security_Group", "resource_id": "sg-0abc123", "region": "ap-northeast-1", "check_id": "EC2-001", "check_name": "SSHポート公開", "severity": "high", "status": "open", "description": "セキュリティグループがSSH(22)を全IPに公開しています", "remediation": "SSHアクセスを特定のIPレンジに制限してください", "compliance_frameworks": []string{"CIS"}},
	}
	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

func (h *CSPMEnhancedHandler) StartScan(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"account_id": id, "scan_status": "scanning", "started_at": time.Now(), "message": "クラウドアカウントのスキャンを開始しました"})
}

func (h *CSPMEnhancedHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_accounts": 3, "total_findings": 47,
		"critical": 9, "high": 28, "medium": 10,
		"avg_posture_score": 7.6,
		"by_provider": []gin.H{
			{"provider": "aws", "posture_score": 7.8, "critical": 3, "high": 12},
			{"provider": "azure", "posture_score": 8.2, "critical": 1, "high": 8},
			{"provider": "gcp", "posture_score": 6.9, "critical": 5, "high": 18},
		},
		"compliance_coverage": []gin.H{
			{"framework": "CIS", "passed": 145, "failed": 23, "rate": 86.3},
			{"framework": "PCI-DSS", "passed": 89, "failed": 11, "rate": 89.0},
			{"framework": "NIST", "passed": 112, "failed": 18, "rate": 86.2},
		},
	})
}
