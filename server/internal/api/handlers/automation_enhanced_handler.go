package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AutomationEnhancedHandler struct{ pool *pgxpool.Pool }

func NewAutomationEnhancedHandler(pool *pgxpool.Pool) *AutomationEnhancedHandler {
	return &AutomationEnhancedHandler{pool: pool}
}

func (h *AutomationEnhancedHandler) ListTriggers(c *gin.Context) {
	triggers := []gin.H{
		{"id": uuid.New(), "name": "クリティカルアラート自動対応", "trigger_type": "alert", "enabled": true, "fire_count": 47, "cooldown_seconds": 300, "last_fired_at": time.Now().Add(-10 * time.Minute)},
		{"id": uuid.New(), "name": "深夜帯インシデント通知", "trigger_type": "schedule", "enabled": true, "fire_count": 12, "cooldown_seconds": 3600},
		{"id": uuid.New(), "name": "外部Webhook受信処理", "trigger_type": "webhook", "enabled": true, "fire_count": 234, "cooldown_seconds": 0},
		{"id": uuid.New(), "name": "マルウェア検出時隔離", "trigger_type": "event", "enabled": true, "fire_count": 8, "cooldown_seconds": 60, "last_fired_at": time.Now().Add(-2 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"triggers": triggers, "total": len(triggers)})
}

func (h *AutomationEnhancedHandler) CreateTrigger(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["fire_count"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *AutomationEnhancedHandler) ListRuns(c *gin.Context) {
	runs := []gin.H{
		{"id": uuid.New(), "trigger_name": "クリティカルアラート自動対応", "status": "completed", "triggered_by": "alert:abc123", "started_at": time.Now().Add(-5 * time.Minute), "completed_at": time.Now().Add(-4 * time.Minute), "duration_ms": 1234},
		{"id": uuid.New(), "trigger_name": "マルウェア検出時隔離", "status": "completed", "triggered_by": "event:malware", "started_at": time.Now().Add(-2 * time.Hour), "completed_at": time.Now().Add(-2*time.Hour + 30*time.Second), "duration_ms": 30000},
		{"id": uuid.New(), "trigger_name": "外部Webhook受信処理", "status": "failed", "triggered_by": "webhook", "started_at": time.Now().Add(-30 * time.Minute), "error_message": "外部APIタイムアウト"},
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs, "total": len(runs)})
}

func (h *AutomationEnhancedHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_triggers": 18, "enabled": 15, "total_runs_today": 89,
		"success_rate": 0.966, "avg_duration_ms": 1450,
		"by_type": []gin.H{
			{"type": "alert", "count": 47},
			{"type": "event", "count": 23},
			{"type": "webhook", "count": 12},
			{"type": "schedule", "count": 7},
		},
	})
}
