package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// signPayload computes an HMAC-SHA256 signature over payload using secret
// and returns a string in the form "sha256=<hex>".
func signPayload(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature reports whether the HMAC-SHA256 signature of payload
// under secret matches sig (which should be in the form "sha256=<hex>").
func VerifyWebhookSignature(secret string, payload []byte, sig string) bool {
	expected := signPayload([]byte(secret), payload)
	return hmac.Equal([]byte(expected), []byte(sig))
}

// WebhookHandler handles CRUD operations for webhook_targets and test deliveries.
type WebhookHandler struct {
	store    *store.WebhookStore
	notifier *notification.WebhookNotifier
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(webhookStore *store.WebhookStore, notifier *notification.WebhookNotifier) *WebhookHandler {
	return &WebhookHandler{store: webhookStore, notifier: notifier}
}

// ─── Request / Response types ──────────────────────────────────────────────

type webhookCreateRequest struct {
	Name    string   `json:"name" binding:"required"`
	URL     string   `json:"url"  binding:"required"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

type webhookUpdateRequest struct {
	Name    string   `json:"name" binding:"required"`
	URL     string   `json:"url"  binding:"required"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

type webhookToggleRequest struct {
	Enabled bool `json:"enabled"`
}

// ─── Handlers ──────────────────────────────────────────────────────────────

// List returns all webhook targets.
// GET /api/v1/webhooks
func (h *WebhookHandler) List(c *gin.Context) {
	targets, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhookターゲットの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": targets})
}

// Create adds a new webhook target.
// POST /api/v1/webhooks
func (h *WebhookHandler) Create(c *gin.Context) {
	var req webhookCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}

	events := req.Events
	if len(events) == 0 {
		events = []string{"alert.critical"}
	}

	target := store.WebhookTarget{
		Name:    req.Name,
		URL:     req.URL,
		Secret:  req.Secret,
		Events:  events,
		Enabled: req.Enabled,
	}

	created, err := h.store.Create(c.Request.Context(), target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhookターゲットの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// Update replaces a webhook target.
// PUT /api/v1/webhooks/:id
func (h *WebhookHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req webhookUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}

	events := req.Events
	if len(events) == 0 {
		events = []string{"alert.critical"}
	}

	target := store.WebhookTarget{
		Name:    req.Name,
		URL:     req.URL,
		Secret:  req.Secret,
		Events:  events,
		Enabled: req.Enabled,
	}

	updated, err := h.store.Update(c.Request.Context(), id, target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhookターゲットの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// Delete removes a webhook target.
// DELETE /api/v1/webhooks/:id
func (h *WebhookHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhookターゲットの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// Toggle enables or disables a webhook target.
// PATCH /api/v1/webhooks/:id/toggle
func (h *WebhookHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req webhookToggleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}
	if err := h.store.SetEnabled(c.Request.Context(), id, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhookターゲットの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": req.Enabled})
}

// Test sends a test payload to the specified webhook target.
// POST /api/v1/webhooks/:id/test
func (h *WebhookHandler) Test(c *gin.Context) {
	id := c.Param("id")

	target, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhookターゲットが見つかりません"})
		return
	}

	testPayload := map[string]interface{}{
		"event":     "test",
		"message":   "EDR Platform Webhook テスト配信",
		"webhook":   target.Name,
		"timestamp": "2026-03-17T00:00:00Z",
	}

	success, statusCode, deliveryErr := notification.DeliverTest(c.Request.Context(), *target, testPayload)
	if deliveryErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   deliveryErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     success,
		"status_code": statusCode,
	})
}

// webhookDeliveryLog is a single delivery record returned by GetDeliveryLog.
type webhookDeliveryLog struct {
	ID         string    `json:"id"`
	WebhookID  string    `json:"webhook_id"`
	EventType  string    `json:"event_type"`
	StatusCode int       `json:"status_code"`
	Attempt    int       `json:"attempt"`
	CreatedAt  time.Time `json:"created_at"`
	DurationMs int64     `json:"duration_ms"`
}

// webhookRetryPolicyRequest is the body for UpdateRetryPolicy.
type webhookRetryPolicyRequest struct {
	MaxRetries        int `json:"max_retries"`
	RetryDelaySeconds int `json:"retry_delay_seconds"`
	TimeoutSeconds    int `json:"timeout_seconds"`
}

// webhookEventTypesRequest is the body for UpdateEventTypes.
type webhookEventTypesRequest struct {
	EventTypes []string `json:"event_types"`
}

// tableExists checks whether a PostgreSQL table exists in the public schema.
func (h *WebhookHandler) tableExists(ctx context.Context, table string) bool {
	var exists bool
	_ = h.store.Pool().QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)`, table,
	).Scan(&exists)
	return exists
}

// GetDeliveryLog returns delivery history for a webhook target.
// GET /api/v1/webhooks/:id/deliveries
func (h *WebhookHandler) GetDeliveryLog(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	if !h.tableExists(ctx, "webhook_deliveries") {
		c.JSON(http.StatusOK, gin.H{
			"deliveries": []webhookDeliveryLog{},
			"note":       "webhook_deliveries テーブルが存在しないため配信ログは空です",
		})
		return
	}

	rows, err := h.store.Pool().Query(ctx, `
		SELECT id, webhook_id, event_type, status_code, attempt, created_at,
		       COALESCE(duration_ms, 0)
		FROM webhook_deliveries
		WHERE webhook_id = $1
		ORDER BY created_at DESC
		LIMIT 100`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "配信ログの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var deliveries []webhookDeliveryLog
	for rows.Next() {
		var d webhookDeliveryLog
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.StatusCode, &d.Attempt, &d.CreatedAt, &d.DurationMs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "配信ログ行のスキャンに失敗しました"})
			return
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if deliveries == nil {
		deliveries = []webhookDeliveryLog{}
	}
	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries})
}

// UpdateRetryPolicy updates the retry policy for a webhook target.
// PUT /api/v1/webhooks/:id/retry-policy
func (h *WebhookHandler) UpdateRetryPolicy(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var req webhookRetryPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}

	// Check if dedicated columns exist; if not, fall back to system_metadata JSONB.
	var colExists bool
	_ = h.store.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'webhook_targets'
			  AND column_name = 'max_retries'
		)`).Scan(&colExists)

	if colExists {
		_, err := h.store.Pool().Exec(ctx, `
			UPDATE webhook_targets
			SET max_retries = $2, retry_delay_seconds = $3, timeout_seconds = $4, updated_at = NOW()
			WHERE id = $1`,
			id, req.MaxRetries, req.RetryDelaySeconds, req.TimeoutSeconds)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "リトライポリシーの更新に失敗しました"})
			return
		}
	} else {
		// Store in system_metadata JSONB column if it exists, otherwise accept silently.
		policyJSON, _ := json.Marshal(map[string]int{
			"max_retries":         req.MaxRetries,
			"retry_delay_seconds": req.RetryDelaySeconds,
			"timeout_seconds":     req.TimeoutSeconds,
		})
		var metaColExists bool
		_ = h.store.Pool().QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'webhook_targets'
				  AND column_name = 'system_metadata'
			)`).Scan(&metaColExists)
		if metaColExists {
			_, err := h.store.Pool().Exec(ctx, `
				UPDATE webhook_targets
				SET system_metadata = COALESCE(system_metadata, '{}'::jsonb) ||
				    jsonb_build_object('retry_policy', $2::jsonb),
				    updated_at = NOW()
				WHERE id = $1`, id, string(policyJSON))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "リトライポリシーの更新に失敗しました"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"max_retries":         req.MaxRetries,
		"retry_delay_seconds": req.RetryDelaySeconds,
		"timeout_seconds":     req.TimeoutSeconds,
	})
}

// UpdateEventTypes updates the subscribed event types for a webhook target.
// PUT /api/v1/webhooks/:id/event-types
func (h *WebhookHandler) UpdateEventTypes(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var req webhookEventTypesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}
	if len(req.EventTypes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "event_typesは1件以上必要です"})
		return
	}

	// Check if events column exists (it does in the current schema as TEXT[]).
	var colExists bool
	_ = h.store.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'webhook_targets'
			  AND column_name = 'events'
		)`).Scan(&colExists)

	if colExists {
		_, err := h.store.Pool().Exec(ctx, `
			UPDATE webhook_targets SET events = $2, updated_at = NOW() WHERE id = $1`,
			id, req.EventTypes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "イベントタイプの更新に失敗しました"})
			return
		}
	} else {
		// Fallback: store in system_metadata if available.
		eventsJSON, _ := json.Marshal(req.EventTypes)
		var metaColExists bool
		_ = h.store.Pool().QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'webhook_targets'
				  AND column_name = 'system_metadata'
			)`).Scan(&metaColExists)
		if metaColExists {
			_, err := h.store.Pool().Exec(ctx, `
				UPDATE webhook_targets
				SET system_metadata = COALESCE(system_metadata, '{}'::jsonb) ||
				    jsonb_build_object('event_types', $2::jsonb),
				    updated_at = NOW()
				WHERE id = $1`, id, string(eventsJSON))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "イベントタイプの更新に失敗しました"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"event_types": req.EventTypes})
}
