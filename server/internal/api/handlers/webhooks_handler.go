package handlers

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/webhooks"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhooksHandler exposes admin CRUD endpoints for webhook_configs and delivery history.
// It uses the webhooks.Dispatcher for in-memory management and the database for persistence.
// This is distinct from the existing WebhookHandler (which manages webhook_targets).
type WebhooksHandler struct {
	dispatcher *webhooks.Dispatcher
	pool       *pgxpool.Pool
}

// validWebhookPlatforms は許可された webhook プラットフォームの集合です。
var validWebhookPlatforms = map[string]struct{}{
	"generic":   {},
	"slack":     {},
	"teams":     {},
	"pagerduty": {},
	"opsgenie":  {},
	"discord":   {},
}

// validWebhookEvents は許可された webhook イベントタイプの集合です。
var validWebhookEvents = map[string]struct{}{
	"alert.created":    {},
	"alert.updated":    {},
	"alert.resolved":   {},
	"incident.created": {},
	"incident.updated": {},
	"agent.offline":    {},
	"agent.online":     {},
	"webhook.test":     {},
}

// validateWebhookURL は webhook の URL を検証します。
// http:// または https:// で始まる必要があります。
func validateWebhookURL(rawURL string) string {
	if rawURL == "" {
		return "url は必須です"
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "url は http:// または https:// で始まる必要があります"
	}
	// ホスト部分が空でないことを確認します
	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "url にホスト名が含まれていません"
	}
	return ""
}

// validateWebhookEvents は webhook イベントリストを検証します。
// 空の場合はデフォルト値 ["alert.created"] を補完します。
func validateWebhookEvents(events *[]string) string {
	if len(*events) == 0 {
		*events = []string{"alert.created"}
		return ""
	}
	for _, ev := range *events {
		if _, ok := validWebhookEvents[ev]; !ok {
			return "無効なイベントタイプが含まれています: " + ev
		}
	}
	return ""
}

// validateWebhookPlatform は webhook プラットフォーム文字列を検証します。
// 空の場合はデフォルト値 "generic" を設定します。
func validateWebhookPlatform(platform *string) string {
	if *platform == "" {
		*platform = "generic"
		return ""
	}
	if _, ok := validWebhookPlatforms[*platform]; !ok {
		return "platform は generic/slack/teams/pagerduty/opsgenie/discord のいずれかを指定してください"
	}
	return ""
}

// validateWebhookRetryCount は retry_count を検証し、0 以下の場合はデフォルト 3 を設定します。
func validateWebhookRetryCount(retryCount *int) {
	if *retryCount <= 0 {
		*retryCount = 3
	}
}

// NewWebhooksHandler creates a new WebhooksHandler.
func NewWebhooksHandler(d *webhooks.Dispatcher, pool *pgxpool.Pool) *WebhooksHandler {
	return &WebhooksHandler{dispatcher: d, pool: pool}
}

// ─── List Configs ──────────────────────────────────────────────────────────

// ListConfigs returns all webhook configs.
// GET /api/v1/admin/webhooks
func (h *WebhooksHandler) ListConfigs(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, url, COALESCE(secret,''), COALESCE(events,'{}'),
		       COALESCE(platform,'generic'), enabled, COALESCE(retry_count,3),
		       COALESCE(last_status,''), last_fired_at,
		       COALESCE(delivery_count,0), COALESCE(failure_count,0),
		       created_at
		FROM webhook_configs
		ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"webhooks": []webhooks.WebhookConfig{}, "total": 0})
		return
	}
	defer rows.Close()

	var cfgs []webhooks.WebhookConfig
	for rows.Next() {
		var wc webhooks.WebhookConfig
		if err := rows.Scan(
			&wc.ID, &wc.Name, &wc.URL, &wc.Secret, &wc.Events,
			&wc.Platform, &wc.Enabled, &wc.RetryCount,
			&wc.LastStatus, &wc.LastFiredAt,
			&wc.DeliveryCount, &wc.FailureCount,
			&wc.CreatedAt,
		); err != nil {
			continue
		}
		wc.Secret = "" // never return secrets in list
		cfgs = append(cfgs, wc)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if cfgs == nil {
		cfgs = []webhooks.WebhookConfig{}
	}
	c.JSON(http.StatusOK, gin.H{"webhooks": cfgs, "total": len(cfgs)})
}

// ─── Create Config ─────────────────────────────────────────────────────────

// CreateConfig creates a new webhook config.
// POST /api/v1/admin/webhooks
func (h *WebhooksHandler) CreateConfig(c *gin.Context) {
	var req struct {
		Name       string   `json:"name" binding:"required"`
		URL        string   `json:"url" binding:"required"`
		Secret     string   `json:"secret"`
		Events     []string `json:"events"`
		Platform   string   `json:"platform"`
		Enabled    bool     `json:"enabled"`
		RetryCount int      `json:"retry_count"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and url are required"})
		return
	}
	if req.Platform == "" {
		req.Platform = "generic"
	}
	if req.RetryCount <= 0 {
		req.RetryCount = 3
	}
	if len(req.Events) == 0 {
		req.Events = []string{"alert.created"}
	}

	var wc webhooks.WebhookConfig
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO webhook_configs (name, url, secret, events, platform, enabled, retry_count)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6, $7)
		RETURNING id, name, url, COALESCE(secret,''), COALESCE(events,'{}'),
		          COALESCE(platform,'generic'), enabled, COALESCE(retry_count,3),
		          COALESCE(last_status,''), last_fired_at,
		          COALESCE(delivery_count,0), COALESCE(failure_count,0),
		          created_at`,
		req.Name, req.URL, req.Secret, req.Events, req.Platform, req.Enabled, req.RetryCount,
	).Scan(
		&wc.ID, &wc.Name, &wc.URL, &wc.Secret, &wc.Events,
		&wc.Platform, &wc.Enabled, &wc.RetryCount,
		&wc.LastStatus, &wc.LastFiredAt,
		&wc.DeliveryCount, &wc.FailureCount,
		&wc.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create webhook"})
		return
	}

	// Register in dispatcher
	cfg := wc
	cfg.Secret = req.Secret // restore secret for dispatcher (not returned in JSON)
	_ = h.dispatcher.AddConfig(&cfg)

	wc.Secret = "" // don't return secret
	c.JSON(http.StatusCreated, wc)
}

// ─── Update Config ─────────────────────────────────────────────────────────

// UpdateConfig updates an existing webhook config.
// PUT /api/v1/admin/webhooks/:id
func (h *WebhooksHandler) UpdateConfig(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name       *string  `json:"name"`
		URL        *string  `json:"url"`
		Secret     *string  `json:"secret"`
		Events     []string `json:"events"`
		Platform   *string  `json:"platform"`
		Enabled    *bool    `json:"enabled"`
		RetryCount *int     `json:"retry_count"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	ctx := c.Request.Context()
	execUpdate := func(field, sql string, args ...interface{}) bool {
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			slog.Warn("webhooks: フィールド更新に失敗しました", "field", field, "id", id, "error", err)
			return false
		}
		return true
	}

	if req.Name != nil {
		if !execUpdate("name", "UPDATE webhook_configs SET name = $2, updated_at = NOW() WHERE id = $1::uuid", id, *req.Name) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if req.URL != nil {
		if !execUpdate("url", "UPDATE webhook_configs SET url = $2, updated_at = NOW() WHERE id = $1::uuid", id, *req.URL) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if req.Secret != nil {
		if !execUpdate("secret", "UPDATE webhook_configs SET secret = NULLIF($2,''), updated_at = NOW() WHERE id = $1::uuid", id, *req.Secret) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if len(req.Events) > 0 {
		if !execUpdate("events", "UPDATE webhook_configs SET events = $2, updated_at = NOW() WHERE id = $1::uuid", id, req.Events) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if req.Platform != nil {
		if !execUpdate("platform", "UPDATE webhook_configs SET platform = $2, updated_at = NOW() WHERE id = $1::uuid", id, *req.Platform) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if req.Enabled != nil {
		if !execUpdate("enabled", "UPDATE webhook_configs SET enabled = $2, updated_at = NOW() WHERE id = $1::uuid", id, *req.Enabled) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}
	if req.RetryCount != nil {
		if !execUpdate("retry_count", "UPDATE webhook_configs SET retry_count = $2, updated_at = NOW() WHERE id = $1::uuid", id, *req.RetryCount) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "webhook updated", "id": id})
}

// ─── Delete Config ─────────────────────────────────────────────────────────

// DeleteConfig removes a webhook config.
// DELETE /api/v1/admin/webhooks/:id
func (h *WebhooksHandler) DeleteConfig(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		"DELETE FROM webhook_configs WHERE id = $1::uuid", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete webhook"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "webhook deleted", "id": id})
}

// ─── Toggle ────────────────────────────────────────────────────────────────

// ToggleConfig enables or disables a webhook.
// PUT /api/v1/admin/webhooks/:id/toggle
func (h *WebhooksHandler) ToggleConfig(c *gin.Context) {
	id := c.Param("id")
	var cur bool
	if err := h.pool.QueryRow(c.Request.Context(),
		"SELECT enabled FROM webhook_configs WHERE id = $1::uuid", id).Scan(&cur); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return
	}
	next := !cur
	if _, err := h.pool.Exec(c.Request.Context(),
		"UPDATE webhook_configs SET enabled = $2, updated_at = NOW() WHERE id = $1::uuid", id, next); err != nil {
		slog.Warn("webhooks: toggle 更新に失敗しました", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook の更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": next})
}

// ─── Test ──────────────────────────────────────────────────────────────────

// TestWebhook sends a test payload to a webhook config.
// POST /api/v1/admin/webhooks/:id/test
func (h *WebhooksHandler) TestWebhook(c *gin.Context) {
	id := c.Param("id")

	var wc webhooks.WebhookConfig
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, name, url, COALESCE(secret,''), COALESCE(events,'{}'),
		       COALESCE(platform,'generic'), enabled, COALESCE(retry_count,3),
		       COALESCE(last_status,''), last_fired_at,
		       COALESCE(delivery_count,0), COALESCE(failure_count,0),
		       created_at
		FROM webhook_configs WHERE id = $1::uuid`, id,
	).Scan(
		&wc.ID, &wc.Name, &wc.URL, &wc.Secret, &wc.Events,
		&wc.Platform, &wc.Enabled, &wc.RetryCount,
		&wc.LastStatus, &wc.LastFiredAt,
		&wc.DeliveryCount, &wc.FailureCount,
		&wc.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return
	}

	testData := map[string]interface{}{
		"message":    "This is a test delivery from EDR Platform.",
		"webhook_id": id,
		"time":       time.Now().Format(time.RFC3339),
	}
	count := h.dispatcher.Dispatch(c.Request.Context(), "webhook.test", testData)
	if count == 0 {
		// Dispatcher doesn't have this config in memory; fire directly via a temp config
		tmp := wc
		tmp.Enabled = true
		tmp.Events = []string{"webhook.test"}
		_ = h.dispatcher.AddConfig(&tmp)
		h.dispatcher.Dispatch(c.Request.Context(), "webhook.test", testData)
	}

	c.JSON(http.StatusOK, gin.H{"message": "test payload dispatched", "id": id})
}

// ─── Delivery History ──────────────────────────────────────────────────────

// GetDeliveries returns recent delivery records for a webhook.
// GET /api/v1/admin/webhooks/:id/deliveries
func (h *WebhooksHandler) GetDeliveries(c *gin.Context) {
	id := c.Param("id")

	type delivery struct {
		ID           string    `json:"id"`
		WebhookID    string    `json:"webhook_id"`
		Event        string    `json:"event"`
		Status       string    `json:"status"`
		StatusCode   int       `json:"status_code"`
		ResponseBody string    `json:"response_body"`
		DurationMS   int       `json:"duration_ms"`
		AttemptedAt  time.Time `json:"attempted_at"`
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, webhook_id::text, COALESCE(event,''), COALESCE(status,''),
		       COALESCE(status_code,0), COALESCE(response_body,''),
		       COALESCE(duration_ms,0), attempted_at
		FROM webhook_deliveries
		WHERE webhook_id = $1::uuid
		ORDER BY attempted_at DESC
		LIMIT 100`, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"deliveries": []delivery{}})
		return
	}
	defer rows.Close()

	var deliveries []delivery
	for rows.Next() {
		var d delivery
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.Event, &d.Status,
			&d.StatusCode, &d.ResponseBody, &d.DurationMS, &d.AttemptedAt,
		); err != nil {
			continue
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if deliveries == nil {
		deliveries = []delivery{}
	}
	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries, "total": len(deliveries)})
}
