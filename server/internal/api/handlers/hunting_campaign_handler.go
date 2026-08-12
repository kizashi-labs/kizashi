package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type HuntingCampaignHandler struct{ pool *pgxpool.Pool }

func NewHuntingCampaignHandler(pool *pgxpool.Pool) *HuntingCampaignHandler {
	return &HuntingCampaignHandler{pool: pool}
}

func (h *HuntingCampaignHandler) ListCampaigns(c *gin.Context) {
	campaigns := []gin.H{
		{"id": uuid.New(), "name": "APT29 ラテラルムーブメント調査", "hypothesis": "APT29がKerberoastingを使用した横移動を実施している可能性", "tactic": "Lateral Movement", "techniques": []string{"T1558.003", "T1021.002"}, "status": "active", "priority": "high", "assigned_analysts": []string{"田中 一郎", "鈴木 花子"}, "iocs_discovered": 7, "hosts_investigated": 23, "start_date": time.Now().Add(-7 * 24 * time.Hour).Format("2006-01-02")},
		{"id": uuid.New(), "name": "データ窃取経路の特定", "hypothesis": "内部ネットワークからC2サーバーへのデータ流出経路が存在する", "tactic": "Exfiltration", "techniques": []string{"T1041", "T1048"}, "status": "completed", "priority": "critical", "iocs_discovered": 12, "hosts_investigated": 45, "conclusion": "DNSトンネリングによるデータ流出を確認。IOC 12件を検出"},
		{"id": uuid.New(), "name": "クレデンシャルハーベスティング検出", "hypothesis": "LSASS ダンプによるクレデンシャル窃取が発生している疑い", "tactic": "Credential Access", "techniques": []string{"T1003.001"}, "status": "planning", "priority": "medium", "iocs_discovered": 0, "hosts_investigated": 0},
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": campaigns, "total": len(campaigns)})
}

func (h *HuntingCampaignHandler) GetCampaign(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": "APT29 ラテラルムーブメント調査",
		"status": "active", "priority": "high",
		"queries": []gin.H{
			{"name": "Kerberoast検出クエリ", "query": "EventID=4769 AND ServiceName!='krbtgt' AND TicketOptions=0x40810000", "hits": 47},
			{"name": "Pass-the-Hash検出", "query": "EventID=4624 AND LogonType=3 AND AuthPackage='NTLM'", "hits": 12},
		},
		"findings": []gin.H{
			{"timestamp": time.Now().Add(-3 * time.Hour), "type": "suspicious_kerberos", "host": "DC-01", "description": "異常なKerberosサービスチケット要求", "severity": "high"},
			{"timestamp": time.Now().Add(-90 * time.Minute), "type": "lateral_movement", "host": "WS-042", "description": "管理者共有への不審なアクセス", "severity": "critical"},
		},
		"assigned_analysts":  []string{"田中 一郎", "鈴木 花子"},
		"iocs_discovered":    7,
		"hosts_investigated": 23,
	})
}

func (h *HuntingCampaignHandler) CreateCampaign(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["status"] = "planning"
	req["iocs_discovered"] = 0
	req["hosts_investigated"] = 0
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *HuntingCampaignHandler) UpdateCampaign(c *gin.Context) {
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

func (h *HuntingCampaignHandler) AddNote(c *gin.Context) {
	campaignID := c.Param("id")
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req["id"] = uuid.New()
	req["campaign_id"] = campaignID
	req["created_at"] = time.Now()
	c.JSON(http.StatusCreated, req)
}

func (h *HuntingCampaignHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_campaigns": 18, "active": 3, "completed": 12, "planning": 3,
		"total_iocs_discovered":    89,
		"total_hosts_investigated": 342,
		"avg_duration_days":        14,
		"success_rate":             0.78,
	})
}
