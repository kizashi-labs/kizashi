package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityAssessmentHandler struct{ pool *pgxpool.Pool }

func NewSecurityAssessmentHandler(pool *pgxpool.Pool) *SecurityAssessmentHandler {
	return &SecurityAssessmentHandler{pool: pool}
}

func (h *SecurityAssessmentHandler) ListAssessments(c *gin.Context) {
	assessments := []gin.H{
		{"id": uuid.New(), "name": "2024年度 ISO27001 ギャップ分析", "assessment_type": "gap_analysis", "framework": "ISO27001", "status": "completed", "assessor": "外部監査法人A", "overall_score": 78.5, "scheduled_date": "2024-02-01", "completed_date": "2024-02-15"},
		{"id": uuid.New(), "name": "セキュリティ成熟度評価 Q1", "assessment_type": "maturity", "framework": "CMMC", "status": "in_progress", "assessor": "田中 一郎", "overall_score": 0, "scheduled_date": time.Now().Add(7 * 24 * time.Hour).Format("2006-01-02")},
		{"id": uuid.New(), "name": "PCI-DSS 準拠性評価", "assessment_type": "compliance", "framework": "PCI-DSS", "status": "review", "assessor": "QSA Partner", "overall_score": 91.2, "scheduled_date": "2024-01-15"},
	}
	c.JSON(http.StatusOK, gin.H{"assessments": assessments, "total": len(assessments)})
}

func (h *SecurityAssessmentHandler) GetAssessment(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": "2024年度 ISO27001 ギャップ分析",
		"assessment_type": "gap_analysis", "framework": "ISO27001", "status": "completed",
		"overall_score": 78.5,
		"findings": []gin.H{
			{"category": "アクセス制御", "severity": "high", "description": "特権アカウントのレビュープロセスが不十分", "recommendation": "四半期ごとのアクセスレビューを実施"},
			{"category": "暗号化", "severity": "medium", "description": "一部レガシーシステムでTLS1.0が使用中", "recommendation": "TLS1.2以上に移行"},
			{"category": "インシデント管理", "severity": "low", "description": "インシデント対応手順書が最新でない", "recommendation": "年次レビューと更新の実施"},
		},
		"recommendations": []gin.H{
			{"priority": 1, "area": "アクセス制御", "action": "PAM製品導入と特権アクセス管理強化"},
			{"priority": 2, "area": "暗号化", "action": "全サービスのTLS1.2+強制移行"},
		},
	})
}

func (h *SecurityAssessmentHandler) CreateAssessment(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["status"] = "draft"
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *SecurityAssessmentHandler) UpdateAssessment(c *gin.Context) {
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

func (h *SecurityAssessmentHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total": 8, "completed": 5, "in_progress": 2, "draft": 1,
		"avg_score": 82.3,
		"by_type": []gin.H{
			{"type": "gap_analysis", "count": 3, "avg_score": 78.5},
			{"type": "maturity", "count": 2, "avg_score": 71.2},
			{"type": "compliance", "count": 3, "avg_score": 91.2},
		},
	})
}
