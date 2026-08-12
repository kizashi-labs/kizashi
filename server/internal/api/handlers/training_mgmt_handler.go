package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TrainingMgmtHandler struct{ pool *pgxpool.Pool }

func NewTrainingMgmtHandler(pool *pgxpool.Pool) *TrainingMgmtHandler {
	return &TrainingMgmtHandler{pool: pool}
}

func (h *TrainingMgmtHandler) ListPrograms(c *gin.Context) {
	programs := []gin.H{
		{"id": uuid.New(), "name": "セキュリティ基礎研修", "program_type": "awareness", "duration_hours": 4.0, "passing_score": 80, "certification_valid_days": 365, "enabled": true},
		{"id": uuid.New(), "name": "フィッシング対策演習", "program_type": "phishing", "duration_hours": 1.0, "passing_score": 70, "certification_valid_days": 180, "enabled": true},
		{"id": uuid.New(), "name": "SOCアナリスト技術研修", "program_type": "technical", "duration_hours": 40.0, "passing_score": 85, "certification_valid_days": 730, "enabled": true},
		{"id": uuid.New(), "name": "GDPR コンプライアンス研修", "program_type": "compliance", "duration_hours": 8.0, "passing_score": 90, "certification_valid_days": 365, "enabled": true},
	}
	c.JSON(http.StatusOK, gin.H{"programs": programs, "total": len(programs)})
}

func (h *TrainingMgmtHandler) CreateProgram(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *TrainingMgmtHandler) ListEnrollments(c *gin.Context) {
	enrollments := []gin.H{
		{"id": uuid.New(), "program_name": "セキュリティ基礎研修", "username": "田中 一郎", "status": "completed", "score": 92.0, "progress_pct": 100, "completed_at": time.Now().Add(-7 * 24 * time.Hour), "expires_at": time.Now().Add(358 * 24 * time.Hour)},
		{"id": uuid.New(), "program_name": "フィッシング対策演習", "username": "鈴木 花子", "status": "in_progress", "score": 0, "progress_pct": 65, "started_at": time.Now().Add(-2 * 24 * time.Hour)},
		{"id": uuid.New(), "program_name": "GDPR コンプライアンス研修", "username": "山田 太郎", "status": "enrolled", "score": 0, "progress_pct": 0, "enrolled_at": time.Now().Add(-1 * 24 * time.Hour)},
		{"id": uuid.New(), "program_name": "セキュリティ基礎研修", "username": "佐藤 次郎", "status": "failed", "score": 62.0, "progress_pct": 100, "completed_at": time.Now().Add(-3 * 24 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"enrollments": enrollments, "total": len(enrollments)})
}

func (h *TrainingMgmtHandler) EnrollUser(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["status"] = "enrolled"
	req["progress_pct"] = 0
	req["enrolled_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *TrainingMgmtHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_programs": 8, "active_programs": 7,
		"total_enrollments": 342, "completed": 198, "in_progress": 87, "enrolled": 45, "failed": 12,
		"overall_completion_rate":     0.579,
		"avg_score":                   84.3,
		"certifications_expiring_30d": 23,
	})
}
