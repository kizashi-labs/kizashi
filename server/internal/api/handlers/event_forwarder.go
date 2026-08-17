package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// EventForwarder subscribes to NATS subjects and forwards events to registered webhooks.
type EventForwarder struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewEventForwarder creates a new EventForwarder.
func NewEventForwarder(pool *pgxpool.Pool, nc *nats.Conn) *EventForwarder {
	return &EventForwarder{pool: pool, nc: nc}
}

// webhookConfig holds a single webhook_configs row.
type webhookConfig struct {
	ID         string
	URL        string
	Secret     []byte
	EventTypes []string
}

// Start subscribes to NATS subjects and forwards matching events to webhooks.
// It blocks until ctx is cancelled.
func (ef *EventForwarder) Start(ctx context.Context) {
	if ef.nc == nil {
		slog.Warn("EventForwarder: NATS接続がnilのためイベント転送をスキップします")
		return
	}

	subjects := []string{
		"alerts.new",
		"agent.offline",
		"agent.online",
		"incident.created",
		"incident.updated",
	}

	subs := make([]*nats.Subscription, 0, len(subjects))

	for _, subject := range subjects {
		subject := subject // capture loop var
		sub, err := ef.nc.Subscribe(subject, func(msg *nats.Msg) {
			ef.handleMessage(ctx, msg.Subject, msg.Data)
		})
		if err != nil {
			metrics.BackgroundFailed("event_forwarder", err, "EventForwarder: NATSサブスクライブに失敗しました", "subject", subject)
			continue
		}
		subs = append(subs, sub)
		slog.Info("EventForwarder: サブスクライブしました", "subject", subject)
	}

	// Unsubscribe when context is cancelled
	go func() {
		<-ctx.Done()
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
		slog.Info("EventForwarder: すべてのサブスクリプションを解除しました")
	}()

	// Keep goroutine alive until context is done
	<-ctx.Done()
}

// handleMessage processes a single NATS message and forwards it to matching webhooks.
func (ef *EventForwarder) handleMessage(ctx context.Context, subject string, payload []byte) {
	// Validate JSON payload
	var raw json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		metrics.BackgroundFailed("event_forwarder", err, "EventForwarder: 不正なJSONペイロード", "subject", subject)
		return
	}

	// Query webhook_configs
	webhooks, err := ef.queryWebhooks(ctx)
	if err != nil {
		// Table may not exist yet — log and return gracefully
		metrics.BackgroundFailed("event_forwarder", err, "EventForwarder: webhook_configsのクエリに失敗しました")
		return
	}

	for _, wh := range webhooks {
		if !ef.matchesEventType(wh.EventTypes, subject) {
			continue
		}
		go ef.deliver(wh, subject, payload)
	}
}

// queryWebhooks fetches enabled webhooks from webhook_configs.
func (ef *EventForwarder) queryWebhooks(ctx context.Context) ([]webhookConfig, error) {
	rows, err := ef.pool.Query(ctx,
		`SELECT id, url, secret, events FROM webhook_configs WHERE enabled = true`,
	)
	if err != nil {
		return nil, fmt.Errorf("webhook_configsクエリエラー: %w", err)
	}
	defer rows.Close()

	var configs []webhookConfig
	for rows.Next() {
		var wh webhookConfig
		if err := rows.Scan(&wh.ID, &wh.URL, &wh.Secret, &wh.EventTypes); err != nil {
			slog.Warn("EventForwarder: webhook_configsの行スキャンエラー", "error", err)
			continue
		}
		configs = append(configs, wh)
	}
	return configs, rows.Err()
}

// matchesEventType checks whether the given NATS subject matches any of the
// configured event types. An empty list is treated as "match all".
func (ef *EventForwarder) matchesEventType(eventTypes []string, subject string) bool {
	if len(eventTypes) == 0 {
		return true
	}
	for _, et := range eventTypes {
		if et == subject || et == "*" {
			return true
		}
	}
	return false
}

// deliver POSTs payload to a single webhook with HMAC signature and event header.
func (ef *EventForwarder) deliver(wh webhookConfig, subject string, payload []byte) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		metrics.BackgroundFailed("event_forwarder", err, "EventForwarder: HTTPリクエスト作成失敗",
			"webhook_id", wh.ID, "url", wh.URL)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-EDR-Event", subject)
	if len(wh.Secret) > 0 {
		req.Header.Set("X-EDR-Signature", signPayload(wh.Secret, payload))
	}

	resp, err := client.Do(req)
	if err != nil {
		metrics.BackgroundFailed("event_forwarder", err, "EventForwarder: Webhook送信エラー",
			"webhook_id", wh.ID, "url", wh.URL, "subject", subject)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		slog.Warn("EventForwarder: WebhookがHTTPエラーを返しました",
			"webhook_id", wh.ID, "url", wh.URL, "subject", subject, "status", resp.StatusCode)
		return
	}

	slog.Info("EventForwarder: Webhook送信成功",
		"webhook_id", wh.ID, "subject", subject, "status", resp.StatusCode)
}
