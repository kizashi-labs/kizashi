package handlers

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SIEMConnectorHandler manages outbound syslog/CEF connections to external SIEM systems.
type SIEMConnectorHandler struct {
	pool *pgxpool.Pool
}

func NewSIEMConnectorHandler(pool *pgxpool.Pool) *SIEMConnectorHandler {
	return &SIEMConnectorHandler{pool: pool}
}

type siemConnectorConfig struct {
	Host              string `json:"host" binding:"required"`
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"` // "udp" or "tcp"
	Format            string `json:"format"`   // "syslog", "cef", "json"
	Facility          int    `json:"facility"`
	SeverityThreshold string `json:"severity_threshold"` // e.g. "low", "medium", "high", "critical"
}

// GetConfig returns the SIEM connector config stored under system_metadata key 'siem_connector'.
// GET /api/v1/admin/siem-connector
func (h *SIEMConnectorHandler) GetConfig(c *gin.Context) {
	var value []byte
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT value FROM system_metadata WHERE key = 'siem_connector' LIMIT 1`,
	).Scan(&value)
	if err != nil {
		// 未設定なら既定値で正しいですが、読めなかった場合に既定値を返すと、
		// 設定済みの転送先が「未設定」として表示されます。
		ReadFailure(c, err, gin.H{
			"host":               "",
			"port":               514,
			"protocol":           "udp",
			"format":             "syslog",
			"facility":           1,
			"severity_threshold": "medium",
		})
		return
	}
	c.Data(http.StatusOK, "application/json", value)
}

// SaveConfig stores the SIEM connector config into system_metadata key 'siem_connector'.
// PUT /api/v1/admin/siem-connector
func (h *SIEMConnectorHandler) SaveConfig(c *gin.Context) {
	var cfg siemConnectorConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト: " + err.Error()})
		return
	}

	if cfg.Protocol != "udp" && cfg.Protocol != "tcp" {
		cfg.Protocol = "udp"
	}
	if cfg.Format == "" {
		cfg.Format = "syslog"
	}
	if cfg.Port <= 0 {
		cfg.Port = 514
	}

	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO system_metadata (key, value, updated_at)
		 VALUES ('siem_connector', $1::jsonb, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		fmt.Sprintf(`{"host":%q,"port":%d,"protocol":%q,"format":%q,"facility":%d,"severity_threshold":%q}`,
			cfg.Host, cfg.Port, cfg.Protocol, cfg.Format, cfg.Facility, cfg.SeverityThreshold),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "SIEM Connector設定を保存しました"})
}

// Test attempts a connection to the configured SIEM host:port and sends a test message.
// POST /api/v1/admin/siem-connector/test
func (h *SIEMConnectorHandler) Test(c *gin.Context) {
	var cfg siemConnectorConfig
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT value FROM system_metadata WHERE key = 'siem_connector' LIMIT 1`,
	).Scan(&cfg)
	if err != nil {
		// Try to bind from JSON body as fallback
		if bindErr := c.ShouldBindJSON(&cfg); bindErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SIEM Connector設定が見つかりません。先に設定を保存してください。"})
			return
		}
	}

	if cfg.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ホストが設定されていません"})
		return
	}
	if cfg.Port <= 0 {
		cfg.Port = 514
	}
	if cfg.Protocol != "tcp" {
		cfg.Protocol = "udp"
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	start := time.Now()

	conn, dialErr := net.DialTimeout(cfg.Protocol, addr, 5*time.Second)
	if dialErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   fmt.Sprintf("%s://%s への接続に失敗しました: %s", cfg.Protocol, addr, dialErr.Error()),
		})
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// RFC 5424 syslog test message
	msg := fmt.Sprintf("<14>1 %s edr-platform test 0 - - Test connection from EDR platform\n",
		time.Now().UTC().Format(time.RFC3339))
	_, writeErr := fmt.Fprint(conn, msg)
	if writeErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "接続は成功しましたがメッセージの送信に失敗しました: " + writeErr.Error(),
		})
		return
	}

	latencyMs := time.Since(start).Milliseconds()
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"latency_ms": latencyMs,
		"message":    fmt.Sprintf("テストメッセージを %s://%s に送信しました", cfg.Protocol, addr),
	})
}

// GetStats returns forwarding statistics from system_metadata.
// GET /api/v1/admin/siem-connector/stats
func (h *SIEMConnectorHandler) GetStats(c *gin.Context) {
	var value []byte
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT value FROM system_metadata WHERE key = 'siem_connector_stats' LIMIT 1`,
	).Scan(&value)
	if err != nil {
		// Return zeroed stats if not yet populated
		ReadFailure(c, err, gin.H{
			"events_forwarded_today": 0,
			"events_forwarded_total": 0,
			"last_forwarded_at":      nil,
			"errors_today":           0,
		})
		return
	}
	c.Data(http.StatusOK, "application/json", value)
}
