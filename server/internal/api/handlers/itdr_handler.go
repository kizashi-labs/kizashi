package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ITDRHandler struct{ pool *pgxpool.Pool }

func NewITDRHandler(pool *pgxpool.Pool) *ITDRHandler { return &ITDRHandler{pool: pool} }

func (h *ITDRHandler) ListIncidents(c *gin.Context) {
	incidents := []gin.H{
		{"id": uuid.New(), "username": "john.doe", "threat_category": "Credential_Stuffing", "risk_score": 8.7, "severity": "critical", "status": "investigating", "indicators": []string{"複数国からの同時ログイン", "パスワードスプレー検出"}, "detected_at": time.Now().Add(-2 * time.Hour)},
		{"id": uuid.New(), "username": "jane.smith", "threat_category": "Impossible_Travel", "risk_score": 7.2, "severity": "high", "status": "open", "indicators": []string{"東京→ニューヨーク 30分以内", "VPN未使用"}, "detected_at": time.Now().Add(-45 * time.Minute)},
		{"id": uuid.New(), "username": "admin.service", "threat_category": "Privileged_Account_Anomaly", "risk_score": 9.1, "severity": "critical", "status": "open", "indicators": []string{"業務時間外の大量データアクセス", "新規デバイスからのログイン"}, "detected_at": time.Now().Add(-20 * time.Minute)},
		{"id": uuid.New(), "username": "bob.wilson", "threat_category": "MFA_Bypass", "risk_score": 6.8, "severity": "high", "status": "resolved", "indicators": []string{"MFAプロンプト疲労攻撃の疑い"}, "detected_at": time.Now().Add(-4 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"incidents": incidents, "total": len(incidents)})
}

func (h *ITDRHandler) GetTopRiskyUsers(c *gin.Context) {
	users := []gin.H{
		{"user_id": "u-001", "username": "admin.service", "risk_score": 9.1, "risk_level": "critical", "privileged": true, "account_type": "service", "risk_factors": []string{"業務時間外アクセス", "新規デバイス", "大量データ操作"}},
		{"user_id": "u-002", "username": "john.doe", "risk_score": 8.7, "risk_level": "critical", "privileged": false, "account_type": "standard", "risk_factors": []string{"クレデンシャルスタッフィング", "複数国ログイン"}},
		{"user_id": "u-003", "username": "jane.smith", "risk_score": 7.2, "risk_level": "high", "privileged": false, "account_type": "standard", "risk_factors": []string{"インポッシブルトラベル"}},
		{"user_id": "u-004", "username": "root.backup", "risk_score": 6.5, "risk_level": "high", "privileged": true, "account_type": "admin", "risk_factors": []string{"共有アカウント使用", "長期未更新パスワード"}},
	}
	c.JSON(http.StatusOK, gin.H{"users": users, "total": len(users)})
}

func (h *ITDRHandler) ListRules(c *gin.Context) {
	rules := []gin.H{
		{"id": uuid.New(), "name": "インポッシブルトラベル", "threat_category": "Impossible_Travel", "severity": "high", "mitre_techniques": []string{"T1078"}, "enabled": true, "hit_count": 12},
		{"id": uuid.New(), "name": "パスワードスプレー検出", "threat_category": "Credential_Stuffing", "severity": "critical", "mitre_techniques": []string{"T1110.003"}, "enabled": true, "hit_count": 8},
		{"id": uuid.New(), "name": "MFA疲労攻撃検出", "threat_category": "MFA_Bypass", "severity": "high", "mitre_techniques": []string{"T1621"}, "enabled": true, "hit_count": 5},
		{"id": uuid.New(), "name": "特権昇格検出", "threat_category": "Privilege_Escalation", "severity": "critical", "mitre_techniques": []string{"T1078.002"}, "enabled": true, "hit_count": 3},
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func (h *ITDRHandler) CreateRule(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["hit_count"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *ITDRHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"active_rules": 18, "incidents_today": 7, "critical": 2, "high": 3, "medium": 2,
		"avg_risk_score": 4.2, "high_risk_users": 8, "privileged_users_monitored": 45,
		"top_threat_categories": []gin.H{
			{"category": "Impossible_Travel", "count": 12},
			{"category": "Credential_Stuffing", "count": 8},
			{"category": "MFA_Bypass", "count": 5},
		},
	})
}
