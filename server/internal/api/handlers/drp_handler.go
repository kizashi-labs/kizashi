package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DRPHandler struct{ pool *pgxpool.Pool }

func NewDRPHandler(pool *pgxpool.Pool) *DRPHandler { return &DRPHandler{pool: pool} }

func (h *DRPHandler) ListMonitors(c *gin.Context) {
	monitors := []gin.H{
		{"id": uuid.New(), "name": "ブランド保護モニタリング", "monitor_type": "brand", "enabled": true, "findings_count": 12, "keywords": []string{"FalconEDR", "Falcon Security"}, "last_scanned_at": time.Now().Add(-1 * time.Hour)},
		{"id": uuid.New(), "name": "クレデンシャル漏洩検知", "monitor_type": "credential", "enabled": true, "findings_count": 3, "domains": []string{"example.com"}, "last_scanned_at": time.Now().Add(-30 * time.Minute)},
		{"id": uuid.New(), "name": "ダークウェブ監視", "monitor_type": "dark_web", "enabled": true, "findings_count": 7, "keywords": []string{"example.com", "admin@example.com"}, "last_scanned_at": time.Now().Add(-2 * time.Hour)},
		{"id": uuid.New(), "name": "ドメイン詐称検知", "monitor_type": "domain", "enabled": true, "findings_count": 5, "domains": []string{"example.com"}, "last_scanned_at": time.Now().Add(-3 * time.Hour)},
		{"id": uuid.New(), "name": "データ漏洩検知", "monitor_type": "data_leak", "enabled": true, "findings_count": 2, "keywords": []string{"confidential", "internal"}, "last_scanned_at": time.Now().Add(-4 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"monitors": monitors, "total": len(monitors)})
}

func (h *DRPHandler) CreateMonitor(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["findings_count"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *DRPHandler) ListFindings(c *gin.Context) {
	findings := []gin.H{
		{"id": uuid.New(), "monitor_name": "クレデンシャル漏洩検知", "title": "企業メールアドレスがダークウェブデータベースで発見", "source": "darkweb_forum", "severity": "critical", "status": "investigating", "found_at": time.Now().Add(-2 * time.Hour)},
		{"id": uuid.New(), "monitor_name": "ブランド保護モニタリング", "title": "フィッシングサイトでのブランド悪用を検出", "source": "phishing_db", "severity": "high", "status": "open", "found_at": time.Now().Add(-4 * time.Hour)},
		{"id": uuid.New(), "monitor_name": "ドメイン詐称検知", "title": "類似ドメイン登録を検出: examp1e.com", "source": "domain_monitor", "severity": "high", "status": "open", "found_at": time.Now().Add(-6 * time.Hour)},
		{"id": uuid.New(), "monitor_name": "データ漏洩検知", "title": "GitHubにハードコードされた認証情報を発見", "source": "github", "severity": "critical", "status": "mitigated", "found_at": time.Now().Add(-1 * 24 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

func (h *DRPHandler) UpdateFinding(c *gin.Context) {
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

func (h *DRPHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_monitors": 5, "active_monitors": 5,
		"total_findings": 29, "open": 12, "investigating": 8, "mitigated": 7, "false_positive": 2,
		"critical_findings": 5, "high_findings": 12,
		"by_type": []gin.H{
			{"type": "brand", "count": 12},
			{"type": "credential", "count": 3},
			{"type": "dark_web", "count": 7},
			{"type": "domain", "count": 5},
			{"type": "data_leak", "count": 2},
		},
	})
}
