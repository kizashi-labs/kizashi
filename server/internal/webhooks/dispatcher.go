// Package webhooks provides a platform-agnostic webhook dispatcher that supports
// Slack Block Kit, MS Teams Adaptive Cards, PagerDuty Events API v2, and generic HTTP.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookConfig describes a registered webhook endpoint.
type WebhookConfig struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Secret        string     `json:"secret"`   // HMAC-SHA256 signing secret
	Events        []string   `json:"events"`   // alert.created, alert.resolved, agent.offline, incident.created
	Platform      string     `json:"platform"` // slack/teams/pagerduty/generic
	Enabled       bool       `json:"enabled"`
	RetryCount    int        `json:"retry_count"` // max retries on failure
	LastStatus    string     `json:"last_status"` // success/failed/pending
	LastFiredAt   *time.Time `json:"last_fired_at"`
	DeliveryCount int64      `json:"delivery_count"`
	FailureCount  int64      `json:"failure_count"`
	CreatedAt     time.Time  `json:"created_at"`
}

// WebhookPayload is the envelope sent to webhook endpoints.
type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Source    string                 `json:"source"` // "edr-platform"
	Signature string                 `json:"signature,omitempty"`
}

// WebhookStats summarises dispatcher activity.
type WebhookStats struct {
	TotalConfigs    int   `json:"total_configs"`
	EnabledConfigs  int   `json:"enabled_configs"`
	TotalDeliveries int64 `json:"total_deliveries"`
	TotalFailures   int64 `json:"total_failures"`
}

// Dispatcher manages a set of WebhookConfigs and dispatches events to matching endpoints.
type Dispatcher struct {
	configs    []*WebhookConfig
	mu         sync.RWMutex
	pool       *pgxpool.Pool
	httpClient *http.Client
}

// NewDispatcher creates a new Dispatcher.
func NewDispatcher(pool *pgxpool.Pool) *Dispatcher {
	return &Dispatcher{
		pool: pool,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// AddConfig appends a webhook configuration.
func (d *Dispatcher) AddConfig(cfg *WebhookConfig) error {
	if cfg.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}
	if cfg.RetryCount <= 0 {
		cfg.RetryCount = 3
	}
	if cfg.Platform == "" {
		cfg.Platform = "generic"
	}

	d.mu.Lock()
	d.configs = append(d.configs, cfg)
	d.mu.Unlock()
	return nil
}

// LoadConfigs replaces the entire config slice (used at startup).
func (d *Dispatcher) LoadConfigs(cfgs []*WebhookConfig) {
	d.mu.Lock()
	d.configs = cfgs
	d.mu.Unlock()
}

// Dispatch fires to all matching enabled configs and returns the number of
// configs that were dispatched to (fired, not necessarily succeeded).
func (d *Dispatcher) Dispatch(ctx context.Context, event string, data map[string]interface{}) int {
	d.mu.RLock()
	matched := make([]*WebhookConfig, 0, len(d.configs))
	for _, cfg := range d.configs {
		if !cfg.Enabled {
			continue
		}
		if matchesEvent(cfg.Events, event) {
			matched = append(matched, cfg)
		}
	}
	d.mu.RUnlock()

	for _, cfg := range matched {
		cfg := cfg
		go func() {
			payload := &WebhookPayload{
				Event:     event,
				Timestamp: time.Now().UTC(),
				Data:      data,
				Source:    "edr-platform",
			}
			if err := d.send(ctx, cfg, payload); err != nil {
				slog.Warn("webhook delivery failed",
					"webhook", cfg.Name,
					"event", event,
					"error", err,
				)
			}
		}()
	}
	return len(matched)
}

// send executes an HTTP POST with retry/backoff for the given config.
func (d *Dispatcher) send(ctx context.Context, cfg *WebhookConfig, payload *WebhookPayload) error {
	var body []byte
	var err error

	switch cfg.Platform {
	case "slack":
		body, err = json.Marshal(d.formatSlack(payload))
	case "teams":
		body, err = json.Marshal(d.formatTeams(payload))
	case "pagerduty":
		body, err = json.Marshal(d.formatPagerDuty(payload))
	default:
		// Generic: sign then marshal
		rawPayload, _ := json.Marshal(payload)
		payload.Signature = d.signPayload(cfg.Secret, rawPayload)
		body, err = json.Marshal(payload)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	maxAttempts := cfg.RetryCount + 1
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "EDR-Platform-Webhook/1.0")
		if cfg.Secret != "" && cfg.Platform == "generic" {
			req.Header.Set("X-EDR-Signature", d.signPayload(cfg.Secret, body))
		}

		resp, err := d.httpClient.Do(req)
		durationMS := int(time.Since(start).Milliseconds())

		if err != nil {
			lastErr = err
			d.recordDelivery(cfg.ID, payload.Event, "failed", 0, err.Error(), durationMS)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			d.recordDelivery(cfg.ID, payload.Event, "success", resp.StatusCode, string(respBody), durationMS)
			d.updateLastFired(cfg.ID, "success")
			return nil
		}

		lastErr = fmt.Errorf("non-2xx response: %d", resp.StatusCode)
		d.recordDelivery(cfg.ID, payload.Event, "failed", resp.StatusCode, string(respBody), durationMS)
	}

	d.updateLastFired(cfg.ID, "failed")
	return lastErr
}

// signPayload computes HMAC-SHA256 of body using secret, returning a hex string.
func (d *Dispatcher) signPayload(secret string, body []byte) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// formatSlack formats a payload as a Slack Block Kit message.
func (d *Dispatcher) formatSlack(p *WebhookPayload) map[string]interface{} {
	text := fmt.Sprintf("*[%s]* Event from EDR Platform at %s",
		p.Event, p.Timestamp.Format(time.RFC3339))

	blocks := []map[string]interface{}{
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": text,
			},
		},
	}

	// Add data fields as context block
	if len(p.Data) > 0 {
		elements := make([]map[string]interface{}, 0, len(p.Data))
		for k, v := range p.Data {
			elements = append(elements, map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s:* %v", k, v),
			})
		}
		blocks = append(blocks, map[string]interface{}{
			"type":     "context",
			"elements": elements,
		})
	}

	return map[string]interface{}{
		"blocks": blocks,
	}
}

// formatTeams formats a payload as an MS Teams Adaptive Card.
func (d *Dispatcher) formatTeams(p *WebhookPayload) map[string]interface{} {
	facts := make([]map[string]interface{}, 0, len(p.Data)+2)
	facts = append(facts, map[string]interface{}{
		"title": "Event",
		"value": p.Event,
	})
	facts = append(facts, map[string]interface{}{
		"title": "Time",
		"value": p.Timestamp.Format(time.RFC3339),
	})
	for k, v := range p.Data {
		facts = append(facts, map[string]interface{}{
			"title": k,
			"value": fmt.Sprintf("%v", v),
		})
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "0076D7",
		"summary":    fmt.Sprintf("EDR Platform: %s", p.Event),
		"sections": []map[string]interface{}{
			{
				"activityTitle":    "EDR Platform Alert",
				"activitySubtitle": p.Timestamp.Format(time.RFC3339),
				"facts":            facts,
			},
		},
	}
}

// formatPagerDuty formats a payload as a PagerDuty Events API v2 trigger.
func (d *Dispatcher) formatPagerDuty(p *WebhookPayload) map[string]interface{} {
	severity := "info"
	if sev, ok := p.Data["severity"].(string); ok && sev != "" {
		switch sev {
		case "critical", "high":
			severity = "critical"
		case "medium":
			severity = "warning"
		case "low":
			severity = "info"
		}
	}

	return map[string]interface{}{
		"routing_key":  "", // populated from cfg.Secret when used as routing_key
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("edr-%s-%d", p.Event, p.Timestamp.Unix()),
		"payload": map[string]interface{}{
			"summary":        fmt.Sprintf("[EDR] %s", p.Event),
			"timestamp":      p.Timestamp.Format(time.RFC3339),
			"source":         p.Source,
			"severity":       severity,
			"custom_details": p.Data,
		},
	}
}

// GetStats returns aggregate statistics for the dispatcher.
func (d *Dispatcher) GetStats() WebhookStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := WebhookStats{TotalConfigs: len(d.configs)}
	for _, cfg := range d.configs {
		if cfg.Enabled {
			stats.EnabledConfigs++
		}
		stats.TotalDeliveries += cfg.DeliveryCount
		stats.TotalFailures += cfg.FailureCount
	}
	return stats
}

// ─── Database helpers ────────────────────────────────────────────────────────

func (d *Dispatcher) recordDelivery(webhookID, event, status string, statusCode int, responseBody string, durationMS int) {
	if d.pool == nil {
		return
	}
	// **配送そのものは終わっていて、残るのは記録だけです。**
	// 呼び出し側はもう次へ進んでいるので（goroutine です）、報告先は
	// 部品ごとの件数になります。落ちると、webhook の設定画面が
	// 「一度も配送していない」と同じ姿になります。
	go func() {
		ctx := context.Background()
		if _, err := d.pool.Exec(ctx, `
			INSERT INTO webhook_deliveries (webhook_id, event, status, status_code, response_body, duration_ms)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			webhookID, event, status, statusCode, responseBody, durationMS,
		); err != nil {
			metrics.BackgroundFailed("webhook_delivery_record", err,
				"webhook の配送履歴を残せませんでした",
				"webhook_id", webhookID, "event", event, "status", status)
		}
		column := "failure_count"
		if status == "success" {
			column = "delivery_count"
		}
		if _, err := d.pool.Exec(ctx,
			"UPDATE webhook_configs SET "+column+" = "+column+" + 1, updated_at = NOW() WHERE id = $1::uuid",
			webhookID); err != nil {
			metrics.BackgroundFailed("webhook_delivery_record", err,
				"webhook の配送件数を更新できませんでした",
				"webhook_id", webhookID, "column", column)
		}
	}()
}

func (d *Dispatcher) updateLastFired(webhookID, status string) {
	if d.pool == nil {
		return
	}
	go func() {
		if _, err := d.pool.Exec(context.Background(), `
			UPDATE webhook_configs
			SET last_fired_at = NOW(), last_status = $2, updated_at = NOW()
			WHERE id = $1::uuid`,
			webhookID, status,
		); err != nil {
			metrics.BackgroundFailed("webhook_delivery_record", err,
				"webhook の最終発火を記録できませんでした",
				"webhook_id", webhookID, "status", status)
		}
	}()
}

// matchesEvent reports whether the given event matches the subscription list.
// A config subscribing to "*" or "all" matches all events.
func matchesEvent(subscribed []string, event string) bool {
	for _, s := range subscribed {
		if s == event || s == "*" || s == "all" {
			return true
		}
	}
	return false
}
