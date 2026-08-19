package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

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

// GetDeliveryLog returns delivery history for a webhook target.
// GET /api/v1/webhooks/:id/deliveries
//
// This used to query webhook_deliveries for event_type, attempt and
// created_at. Measured against the migrated schema, three of those columns do
// not exist, so every call was 42703 -> 500. Renaming them would not have been
// enough: webhook_deliveries belongs to the other webhook subsystem and is
// keyed to webhook_configs, while the :id here is a webhook_targets id — a
// corrected query would have matched no row for any id this route can be
// given, turning the 500 into an empty 200 that reads as "no deliveries yet".
// Migration 376 adds the table that internal/notification now writes per
// attempt, and this reads that.
func (h *WebhookHandler) GetDeliveryLog(c *gin.Context) {
	id := c.Param("id")

	deliveries, err := h.store.ListDeliveries(c.Request.Context(), id, store.DeliveryHistoryLimit)
	if err != nil {
		if errors.Is(err, store.ErrWebhookNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "指定されたwebhookが見つかりません"})
			return
		}
		slog.Warn("webhook配信ログの取得に失敗しました", "webhook", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "配信ログの取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries, "total": len(deliveries)})
}

// UpdateRetryPolicy updates the retry policy for a webhook target.
// PUT /api/v1/webhooks/:id/retry-policy
//
// This used to probe for a max_retries column, fall back to probing for a
// system_metadata column, and when neither existed — which was always, no
// migration created either — return 200 echoing the request body. The response
// is indistinguishable from a stored value, so a policy the operator set was
// discarded on every call, including against a webhook id that does not exist.
// Migration 375 creates the columns; the probing and the fallback are gone.
func (h *WebhookHandler) UpdateRetryPolicy(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var req webhookRetryPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です: " + err.Error()})
		return
	}

	policy := store.WebhookRetryPolicy{
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
		TimeoutSeconds:    req.TimeoutSeconds,
	}
	if !policy.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
			"リトライ設定が範囲外です (max_retries 0-%d, retry_delay_seconds 0-%d, timeout_seconds 1-%d)",
			store.MaxRetriesLimit, store.RetryDelaySecondsLimit, store.TimeoutSecondsLimit)})
		return
	}

	if err := h.store.UpdateRetryPolicy(ctx, id, policy); err != nil {
		if errors.Is(err, store.ErrWebhookNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "webhookが見つかりません"})
			return
		}
		slog.Error("リトライポリシーの更新に失敗しました", "webhook_id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リトライポリシーの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"max_retries":         policy.MaxRetries,
		"retry_delay_seconds": policy.RetryDelaySeconds,
		"timeout_seconds":     policy.TimeoutSeconds,
	})
}

// UpdateEventTypes updates the subscribed event types for a webhook target.
// PUT /api/v1/webhooks/:id/event-types
//
// Same shape as UpdateRetryPolicy above: the events column has always existed,
// but the surrounding probe-and-fall-back-to-system_metadata structure meant a
// schema change would have turned this silently inert too, and neither arm
// noticed that the webhook did not exist.
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

	if err := h.store.UpdateEvents(ctx, id, req.EventTypes); err != nil {
		if errors.Is(err, store.ErrWebhookNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "webhookが見つかりません"})
			return
		}
		slog.Error("イベントタイプの更新に失敗しました", "webhook_id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "イベントタイプの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"event_types": req.EventTypes})
}
