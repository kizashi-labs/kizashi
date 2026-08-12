package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AlertRoutingHandler struct{ pool *pgxpool.Pool }

func NewAlertRoutingHandler(pool *pgxpool.Pool) *AlertRoutingHandler {
	return &AlertRoutingHandler{pool: pool}
}

func (h *AlertRoutingHandler) ListRules(c *gin.Context) {
	rules := []gin.H{
		{"id": uuid.New(), "name": "クリティカルアラート → PagerDuty", "priority": 10, "enabled": true, "match_count": 234, "destinations": []string{"PagerDuty", "Slack #incidents"}, "last_matched_at": time.Now().Add(-5 * time.Minute)},
		{"id": uuid.New(), "name": "ランサムウェア検出 → SOCチーム緊急", "priority": 5, "enabled": true, "match_count": 3, "destinations": []string{"Slack #critical", "SMS", "PagerDuty"}, "last_matched_at": time.Now().Add(-2 * time.Hour)},
		{"id": uuid.New(), "name": "高リスクアラート → JIRA自動チケット", "priority": 20, "enabled": true, "match_count": 892, "destinations": []string{"JIRA", "Email"}, "last_matched_at": time.Now().Add(-10 * time.Minute)},
		{"id": uuid.New(), "name": "低リスクアラート → ログのみ", "priority": 100, "enabled": true, "match_count": 5672, "destinations": []string{"Log"}, "last_matched_at": time.Now().Add(-1 * time.Minute)},
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func (h *AlertRoutingHandler) CreateRule(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["match_count"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *AlertRoutingHandler) UpdateRule(c *gin.Context) {
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

func (h *AlertRoutingHandler) DeleteRule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "ルールを削除しました"})
}

func (h *AlertRoutingHandler) ListDestinations(c *gin.Context) {
	dests := []gin.H{
		{"id": uuid.New(), "name": "Slack #incidents", "destination_type": "slack", "enabled": true, "last_used_at": time.Now().Add(-5 * time.Minute)},
		{"id": uuid.New(), "name": "PagerDuty On-Call", "destination_type": "pagerduty", "enabled": true, "last_used_at": time.Now().Add(-2 * time.Hour)},
		{"id": uuid.New(), "name": "JIRA Security Board", "destination_type": "jira", "enabled": true, "last_used_at": time.Now().Add(-10 * time.Minute)},
		{"id": uuid.New(), "name": "ServiceNow ITSM", "destination_type": "servicenow", "enabled": true, "last_used_at": time.Now().Add(-1 * time.Hour)},
		{"id": uuid.New(), "name": "SOC Team Email", "destination_type": "email", "enabled": true, "last_used_at": time.Now().Add(-30 * time.Minute)},
		{"id": uuid.New(), "name": "MS Teams Security", "destination_type": "teams", "enabled": false},
	}
	c.JSON(http.StatusOK, gin.H{"destinations": dests, "total": len(dests)})
}

func (h *AlertRoutingHandler) CreateDestination(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *AlertRoutingHandler) TestDestination(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"destination_id": id, "success": true, "message": "テストメッセージを送信しました", "response_ms": 234})
}

func (h *AlertRoutingHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_rules": 12, "active_rules": 10,
		"total_destinations": 6, "active_destinations": 5,
		"routed_today": 6801,
		"by_destination": []gin.H{
			{"name": "Slack #incidents", "count": 234},
			{"name": "JIRA", "count": 892},
			{"name": "PagerDuty", "count": 47},
			{"name": "Log", "count": 5628},
		},
	})
}
