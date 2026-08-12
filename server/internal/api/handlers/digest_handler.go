package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/scheduler"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DigestHandler provides endpoints for triggering, configuring and reviewing
// alert digests. Config is persisted in alert_digest_config (singleton row)
// and every send is recorded in alert_digest_runs.
type DigestHandler struct {
	sender *scheduler.AlertDigestSender
	pool   *pgxpool.Pool
}

// NewDigestHandler creates a new DigestHandler.
func NewDigestHandler(sender *scheduler.AlertDigestSender, pool *pgxpool.Pool) *DigestHandler {
	return &DigestHandler{sender: sender, pool: pool}
}

// defaultDigestConfig mirrors the frontend's DigestConfig shape.
func defaultDigestConfig() gin.H {
	return gin.H{
		"daily": gin.H{
			"enabled":      false,
			"send_time":    "08:00",
			"recipients":   []string{},
			"min_severity": 5,
			"sections": gin.H{
				"alert_counts": true, "top_agents": true, "top_alert_types": true,
				"open_incidents": true, "compliance_score": false,
			},
		},
		"weekly": gin.H{
			"enabled":     false,
			"day_of_week": "Monday",
			"send_time":   "08:00",
			"recipients":  []string{},
			"extra_sections": gin.H{
				"agent_health": true, "vulnerability_summary": false, "soc_ticket_summary": false,
			},
		},
	}
}

// TriggerDigest handles POST /admin/digest/trigger.
// Body: {"period": "daily|weekly"}
func (h *DigestHandler) TriggerDigest(c *gin.Context) {
	var req struct {
		Period string `json:"period" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if req.Period != "daily" && req.Period != "weekly" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "period must be 'daily' or 'weekly'"})
		return
	}
	if err := h.sender.SendNow(c.Request.Context(), req.Period); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "triggered", "period": req.Period})
}

// GetDigestConfig handles GET /admin/digest/config.
// Returns the persisted config, or defaults when none has been saved yet
// (previously this endpoint returned hard-coded values).
func (h *DigestHandler) GetDigestConfig(c *gin.Context) {
	var raw []byte
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT config FROM alert_digest_config WHERE id = 1`).Scan(&raw)
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusOK, defaultDigestConfig())
		return
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil || len(cfg) == 0 {
		c.JSON(http.StatusOK, defaultDigestConfig())
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// UpdateDigestConfig handles PUT /admin/digest/config.
func (h *DigestHandler) UpdateDigestConfig(c *gin.Context) {
	var cfg map[string]any
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}
	if _, err := h.pool.Exec(c.Request.Context(), `
		INSERT INTO alert_digest_config (id, config, updated_at)
		VALUES (1, $1::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()`, raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "設定を保存しました"})
}

// GetDigestHistory handles GET /admin/digest/history.
func (h *DigestHandler) GetDigestHistory(c *gin.Context) {
	history := []gin.H{}
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, type, sent_at, recipients_count, total_alerts, status
		FROM alert_digest_runs ORDER BY sent_at DESC LIMIT 50`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, typ, status string
			var sentAt time.Time
			var recipients, total int
			if err := rows.Scan(&id, &typ, &sentAt, &recipients, &total, &status); err != nil {
				continue
			}
			history = append(history, gin.H{
				"id": id, "type": typ,
				"sent_at":          sentAt.UTC().Format(time.RFC3339),
				"recipients_count": recipients,
				"total_alerts":     total,
				"status":           status,
			})
		}
	}
	c.JSON(http.StatusOK, history)
}

// GetDigestStats handles GET /admin/digest/stats.
func (h *DigestHandler) GetDigestStats(c *gin.Context) {
	ctx := c.Request.Context()
	var sentThisMonth int
	var lastSent *time.Time
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alert_digest_runs WHERE sent_at >= date_trunc('month', NOW())`).Scan(&sentThisMonth)
	_ = h.pool.QueryRow(ctx, `SELECT MAX(sent_at) FROM alert_digest_runs`).Scan(&lastSent)

	// Distinct recipients across daily+weekly config.
	recipients := 0
	var raw []byte
	if err := h.pool.QueryRow(ctx, `SELECT config FROM alert_digest_config WHERE id = 1`).Scan(&raw); err == nil {
		var cfg struct {
			Daily struct {
				Recipients []string `json:"recipients"`
			} `json:"daily"`
			Weekly struct {
				Recipients []string `json:"recipients"`
			} `json:"weekly"`
		}
		if json.Unmarshal(raw, &cfg) == nil {
			seen := map[string]bool{}
			for _, r := range append(cfg.Daily.Recipients, cfg.Weekly.Recipients...) {
				seen[r] = true
			}
			recipients = len(seen)
		}
	}

	// Next scheduled send: tomorrow 08:00 JST (the scheduler's daily slot).
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 23, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}

	stats := gin.H{
		"sent_this_month": sentThisMonth,
		"recipients":      recipients,
		"last_sent":       "",
		"next_scheduled":  next.Format(time.RFC3339),
	}
	if lastSent != nil {
		stats["last_sent"] = lastSent.UTC().Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, stats)
}
