package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"io"
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
		metrics.BackgroundFailed("webhook_notifier", err, "WebhookNotifier: ターゲットの取得に失敗しました", "event", event)
		return
	}

	payload, err := buildPayload(event, rawData)
	if err != nil {
		metrics.BackgroundFailed("webhook_notifier", err, "WebhookNotifier: ペイロード構築失敗")
		return
	}

	for _, t := range targets {
		t := t // capture
		go w.deliver(ctx, t, event, payload)
	}
}

// attemptOutcome is what one HTTP attempt tells us about whether to try again.
type attemptOutcome int

const (
	// outcomeDelivered — the endpoint accepted it.
	outcomeDelivered attemptOutcome = iota
	// outcomeRetryable — nobody answered, or the endpoint said "not now":
	// a transport error, any 5xx, or 429.
	outcomeRetryable
	// outcomeRejected — the endpoint answered and will answer the same way
	// however many times we ask (4xx other than 429). Retrying a rejected
	// payload only multiplies the load on an endpoint that is already saying no.
	outcomeRejected
)

// classifyAttempt decides whether a delivery is worth repeating.
func classifyAttempt(statusCode int, err error) attemptOutcome {
	if err != nil {
		return outcomeRetryable
	}
	switch {
	case statusCode >= 200 && statusCode < 300:
		return outcomeDelivered
	case statusCode == http.StatusTooManyRequests, statusCode >= 500:
		return outcomeRetryable
	default:
		return outcomeRejected
	}
}

// retryBackoff is how long to wait before attempt number `attempt` (1-based for
// the first retry). It grows linearly from the configured base delay so a
// struggling endpoint is not hit at a fixed rate, and it is clamped so a
// generous policy cannot park a goroutine for an unbounded time.
func retryBackoff(policy store.WebhookRetryPolicy, attempt int) time.Duration {
	d := time.Duration(policy.RetryDelaySeconds) * time.Second * time.Duration(attempt)
	if max := time.Duration(store.RetryDelaySecondsLimit) * time.Second; d > max {
		d = max
	}
	return d
}

// deliver POSTs the payload to a single webhook target and records the result.
//
// It used to make exactly one attempt with a hardcoded 10 second timeout: one
// 502 from the customer's SIEM dropped the notification with nothing but a Warn
// line, and the endpoint that was supposed to configure retries stored nothing.
// The target's policy is now honoured — see store.WebhookRetryPolicy.
func (w *WebhookNotifier) deliver(ctx context.Context, target store.WebhookTarget, event string, payload []byte) {
	policy := target.RetryPolicy
	if policy.TimeoutSeconds <= 0 {
		// A target read by a path that does not select the policy would
		// otherwise get a zero timeout, which fails instantly on every attempt.
		policy.TimeoutSeconds = 10
	}
	client := &http.Client{Timeout: time.Duration(policy.TimeoutSeconds) * time.Second}

	var statusCode int
	for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryBackoff(policy, attempt)):
			}
		}

		started := time.Now()
		code, err := w.attempt(ctx, client, target, event, payload)
		outcome := classifyAttempt(code, err)
		w.recordAttempt(target, event, attempt+1, code, err, time.Since(started),
			outcome == outcomeDelivered)

		switch outcome {
		case outcomeDelivered:
			slog.Debug("WebhookNotifier: 配信成功",
				"webhook", target.Name, "status", code, "event", event, "attempt", attempt+1)
			w.recordStatus(target, code)
			return
		case outcomeRejected:
			slog.Warn("WebhookNotifier: 配信が拒否されました (再試行しません)",
				"webhook", target.Name, "status", code, "event", event)
			w.recordStatus(target, code)
			return
		case outcomeRetryable:
			statusCode = code
			slog.Warn("WebhookNotifier: 配信失敗 (再試行対象)",
				"webhook", target.Name, "url", target.URL, "status", code,
				"event", event, "attempt", attempt+1, "of", policy.MaxRetries+1, "error", err)
		}
	}

	slog.Warn("WebhookNotifier: 再試行を使い切りました",
		"webhook", target.Name, "url", target.URL, "event", event,
		"attempts", policy.MaxRetries+1)
	w.recordStatus(target, statusCode)
}

// attempt performs one HTTP POST and returns its status code (0 if nobody
// answered).
func (w *WebhookNotifier) attempt(
	ctx context.Context,
	client *http.Client,
	target store.WebhookTarget,
	event string,
	payload []byte,
) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
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

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		// Drain before closing so the connection can be reused. A retry loop
		// hits the same endpoint several times in a row, and an undrained body
		// forces a new TCP handshake for each attempt. Bounded so a large
		// error page cannot make the drain the expensive part.
		_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
		_ = resp.Body.Close()
	}()
	return resp.StatusCode, nil
}

// recordStatus stores the outcome of the last attempt. It uses a background
// context because the delivery context may already be done by the time the
// retries are exhausted.
func (w *WebhookNotifier) recordStatus(target store.WebhookTarget, statusCode int) {
	if statusCode <= 0 {
		return
	}
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.store.UpdateDeliveryStatus(updateCtx, target.ID, statusCode); err != nil {
		slog.Warn("WebhookNotifier: 配信ステータスの保存に失敗しました",
			"webhook", target.Name, "error", err)
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

// recordAttempt appends one attempt to the target's delivery history.
//
// Every attempt is recorded, not just the last one, because the sequence is
// what makes the retry policy legible: an endpoint that answered on the first
// try and one that needed all of its retries both end with the same final
// status stamped on the target. Failing to record is logged and otherwise
// ignored — history is diagnostics, and losing a row must not lose the
// notification.
//
// Like recordStatus this uses a background context: the delivery context may
// already be done by the time a late attempt finishes.
func (w *WebhookNotifier) recordAttempt(
	target store.WebhookTarget,
	event string,
	attempt int,
	statusCode int,
	attemptErr error,
	elapsed time.Duration,
	delivered bool,
) {
	msg := ""
	if attemptErr != nil {
		msg = attemptErr.Error()
	}

	recCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.store.RecordDelivery(recCtx, store.WebhookDelivery{
		WebhookID:  target.ID,
		Event:      event,
		Attempt:    attempt,
		StatusCode: statusCode,
		Error:      msg,
		DurationMs: elapsed.Milliseconds(),
		Delivered:  delivered,
	}); err != nil {
		slog.Warn("WebhookNotifier: 配信履歴の記録に失敗しました",
			"webhook", target.Name, "event", event, "attempt", attempt, "error", err)
	}
}
