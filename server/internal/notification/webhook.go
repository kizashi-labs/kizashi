package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/nats-io/nats.go"
)

// WebhookNotifier subscribes to NATS alert and agent event subjects and
// delivers JSON payloads to registered webhook_targets via HTTP POST.
type WebhookNotifier struct {
	store *store.WebhookStore
	nc    *nats.Conn
}

// NewWebhookNotifier creates a WebhookNotifier. Call Start to begin NATS subscriptions.
func NewWebhookNotifier(webhookStore *store.WebhookStore, nc *nats.Conn) *WebhookNotifier {
	return &WebhookNotifier{store: webhookStore, nc: nc}
}

// Start subscribes to NATS subjects and begins dispatching webhooks.
// It blocks until ctx is cancelled.
func (w *WebhookNotifier) Start(ctx context.Context) {
	if w.nc == nil {
		slog.Warn("WebhookNotifier: NATSが接続されていないためスキップします")
		return
	}

	// Subscribe to all alert topics
	alertSub, err := w.nc.Subscribe("alerts.>", func(msg *nats.Msg) {
		event := w.alertEventType(msg.Subject)
		w.dispatch(ctx, event, msg.Data)
	})
	if err != nil {
		slog.Warn("WebhookNotifier: アラートサブスクリプション失敗", "error", err)
	}

	// Subscribe to agent events (e.g. agent.events.<agentID>.offline)
	agentSub, err := w.nc.Subscribe("agent.events.>", func(msg *nats.Msg) {
		event := w.agentEventType(msg.Subject)
		if event == "" {
			return
		}
		w.dispatch(ctx, event, msg.Data)
	})
	if err != nil {
		slog.Warn("WebhookNotifier: エージェントイベントサブスクリプション失敗", "error", err)
	}

	<-ctx.Done()

	if alertSub != nil {
		_ = alertSub.Unsubscribe()
	}
	if agentSub != nil {
		_ = agentSub.Unsubscribe()
	}
}

// alertEventType maps a NATS subject like "alerts.critical" or "alerts.new" to a webhook event name.
func (w *WebhookNotifier) alertEventType(subject string) string {
	parts := strings.Split(subject, ".")
	if len(parts) < 2 {
		return "alert.any"
	}
	switch strings.ToLower(parts[1]) {
	case "critical":
		return "alert.critical"
	case "high":
		return "alert.high"
	default:
		return "alert.any"
	}
}

// agentEventType maps a NATS subject to a webhook event name.
// Returns "" if the event type is not one we dispatch webhooks for.
func (w *WebhookNotifier) agentEventType(subject string) string {
	lower := strings.ToLower(subject)
	if strings.HasSuffix(lower, ".offline") || strings.Contains(lower, ".offline.") {
		return "agent.offline"
	}
	return ""
}

// dispatch looks up matching enabled webhooks and fires each one in its own goroutine.
func (w *WebhookNotifier) dispatch(ctx context.Context, event string, rawData []byte) {
	targets, err := w.store.ListEnabledForEvent(ctx, event)
	if err != nil {
		slog.Warn("WebhookNotifier: ターゲットの取得に失敗しました", "event", event, "error", err)
		return
	}

	payload, err := buildPayload(event, rawData)
	if err != nil {
		slog.Warn("WebhookNotifier: ペイロード構築失敗", "error", err)
		return
	}

	for _, t := range targets {
		t := t // capture
		go w.deliver(ctx, t, event, payload)
	}
}

// deliver POSTs the payload to a single webhook target and records the result.
func (w *WebhookNotifier) deliver(ctx context.Context, target store.WebhookTarget, event string, payload []byte) {
	deliverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(deliverCtx, http.MethodPost, target.URL, bytes.NewReader(payload))
	if err != nil {
		slog.Warn("WebhookNotifier: リクエスト構築失敗",
			"webhook", target.Name, "url", target.URL, "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "EDR-Platform-Webhook/1.0")
	req.Header.Set("X-Webhook-Event", event)

	// HMAC-SHA256 signing
	if target.Secret != "" {
		mac := hmac.New(sha256.New, []byte(target.Secret))
		mac.Write(payload)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Hub-Signature-256", sig)
		req.Header.Set("X-EDR-Signature", sig)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	statusCode := 0
	if err != nil {
		slog.Warn("WebhookNotifier: 配信失敗",
			"webhook", target.Name, "url", target.URL, "error", err)
		statusCode = 0
	} else {
		statusCode = resp.StatusCode
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			slog.Debug("WebhookNotifier: 配信成功",
				"webhook", target.Name, "status", resp.StatusCode, "event", event)
		} else {
			slog.Warn("WebhookNotifier: 配信で非2xxレスポンス",
				"webhook", target.Name, "status", resp.StatusCode, "event", event)
		}
	}

	// Update last_triggered_at and last_status (fire-and-forget with background context)
	if statusCode > 0 {
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer updateCancel()
		if err := w.store.UpdateDeliveryStatus(updateCtx, target.ID, statusCode); err != nil {
			slog.Warn("WebhookNotifier: 配信ステータスの保存に失敗しました",
				"webhook", target.Name, "error", err)
		}
	}
}

// DeliverTest sends a test JSON payload to the given target and returns
// (success, statusCode, error). It is exported so the webhook handler can call it.
func DeliverTest(ctx context.Context, target store.WebhookTarget, payload interface{}) (bool, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return false, 0, fmt.Errorf("テストペイロードのシリアライズに失敗しました: %w", err)
	}

	deliverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(deliverCtx, http.MethodPost, target.URL, bytes.NewReader(data))
	if err != nil {
		return false, 0, fmt.Errorf("リクエストの構築に失敗しました: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "EDR-Platform-Webhook/1.0")
	req.Header.Set("X-Webhook-Event", "test")

	if target.Secret != "" {
		mac := hmac.New(sha256.New, []byte(target.Secret))
		mac.Write(data)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Hub-Signature-256", sig)
		req.Header.Set("X-EDR-Signature", sig)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("テスト配信に失敗しました: %w", err)
	}
	defer resp.Body.Close()

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	return success, resp.StatusCode, nil
}

// buildPayload constructs the JSON payload for a webhook delivery.
func buildPayload(event string, rawData []byte) ([]byte, error) {
	envelope := map[string]interface{}{
		"event":     event,
		"data":      json.RawMessage(rawData),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("webhook ペイロードのシリアライズに失敗しました: %w", err)
	}
	return data, nil
}
