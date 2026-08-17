package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
)

// EventStreamHandler provides Server-Sent Events (SSE) for real-time event feed.
type EventStreamHandler struct {
	nc *nats.Conn
}

// NewEventStreamHandler creates an EventStreamHandler backed by a NATS connection.
// nc may be nil, in which case mock events are emitted every 5 s for testing.
func NewEventStreamHandler(nc *nats.Conn) *EventStreamHandler {
	return &EventStreamHandler{nc: nc}
}

// streamSubjects maps a logical event type to the NATS subjects that produce it.
var streamSubjects = map[string][]string{
	"alert":    {"alerts.new"},
	"agent":    {"agent.offline", "agent.online"},
	"incident": {"incident.created", "incident.updated"},
}

// sseEvent is the envelope written to each SSE message.
type sseEvent struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// Stream handles GET /api/v1/stream
//
// Query parameters:
//
//	types — comma-separated list of: alerts, agents, incidents
//	         (omit or use "*" to subscribe to all)
//
// The endpoint sets SSE headers and streams events until the client disconnects.
// A ping frame is sent every 30 s to keep the connection alive.
func (h *EventStreamHandler) Stream(c *gin.Context) {
	// ── SSE headers ───────────────────────────────────────────────────────
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	// ── Parse requested event types ───────────────────────────────────────
	rawTypes := c.Query("types")
	requestedTypes := parseEventTypes(rawTypes)

	// ── Client disconnect signal ──────────────────────────────────────────
	clientGone := c.Request.Context().Done()

	// ── NATS path ─────────────────────────────────────────────────────────
	if h.nc != nil {
		h.streamFromNATS(c, requestedTypes, clientGone)
		return
	}

	// ── NATS unavailable: send one disconnected notice then keep connection alive ──
	h.streamNATSUnavailable(c, clientGone)
}

// streamFromNATS subscribes to NATS subjects based on the requested types and
// forwards messages via gin SSE until the client disconnects.
func (h *EventStreamHandler) streamFromNATS(
	c *gin.Context,
	types []string,
	clientGone <-chan struct{},
) {
	msgCh := make(chan *nats.Msg, 64)

	// Subscribe to subjects for each requested type.
	var subs []*nats.Subscription
	for _, t := range types {
		subjects, ok := streamSubjects[t]
		if !ok {
			continue
		}
		for _, subj := range subjects {
			eventType := t // capture for closure
			sub, err := h.nc.Subscribe(subj, func(msg *nats.Msg) {
				// Wrap the raw NATS payload in our SSE envelope before enqueuing.
				env := sseEvent{
					Type:      eventType,
					Timestamp: time.Now().Unix(),
					Payload:   json.RawMessage(msg.Data),
				}
				data, err := json.Marshal(env)
				if err != nil {
					slog.Warn("SSEイベントのシリアライズに失敗しました", "error", err)
					return
				}
				// Create a synthetic nats.Msg carrying the marshalled envelope.
				synthetic := &nats.Msg{Data: data}
				select {
				case msgCh <- synthetic:
				default:
					// Drop message if channel is full (slow consumer).
					slog.Warn("SSEチャンネルが満杯です。メッセージをドロップします", "subject", msg.Subject)
				}
			})
			if err != nil {
				metrics.BackgroundFailed("event_stream", err, "NATSサブスクライブに失敗しました", "subject", subj)
				continue
			}
			subs = append(subs, sub)
		}
	}

	// Drain subscriptions on exit.
	defer func() {
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
	}()

	c.Stream(func(w io.Writer) bool {
		select {
		case msg := <-msgCh:
			c.SSEvent("message", string(msg.Data))
			return true
		case <-clientGone:
			return false
		case <-time.After(30 * time.Second):
			c.SSEvent("ping", fmt.Sprintf("%d", time.Now().Unix()))
			return true
		}
	})
}

// streamNATSUnavailable notifies the client that the event broker is unreachable
// and sends keepalive pings so the connection stays open.
// No synthetic/fake event payloads are emitted.
func (h *EventStreamHandler) streamNATSUnavailable(
	c *gin.Context,
	clientGone <-chan struct{},
) {
	slog.Warn("SSEストリーム: NATSが利用不可のためリアルタイムイベントを配信できません")

	// Send an immediate status notice so the client knows what is happening.
	notice, _ := json.Marshal(map[string]string{
		"status":  "broker_unavailable",
		"message": "イベントブローカーに接続できません。リアルタイムイベントは配信されません。",
	})
	c.SSEvent("status", string(notice))

	// Keep the SSE connection alive with 30-second pings until the client disconnects.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	c.Stream(func(w io.Writer) bool {
		select {
		case <-clientGone:
			return false
		case <-ticker.C:
			c.SSEvent("ping", fmt.Sprintf("%d", time.Now().Unix()))
			return true
		}
	})
}

// parseEventTypes converts a comma-separated types query value into a deduplicated
// slice of canonical event type strings.  An empty/missing value or "*" returns
// all supported types.
func parseEventTypes(raw string) []string {
	all := []string{"alert", "agent", "incident"}
	if raw == "" || raw == "*" {
		return all
	}

	seen := make(map[string]bool)
	var result []string
	for _, part := range strings.Split(raw, ",") {
		t := strings.TrimSpace(strings.ToLower(part))
		// Accept plural variants used by callers (e.g. "alerts" → "alert").
		t = strings.TrimSuffix(t, "s")
		if t == "" || seen[t] {
			continue
		}
		// Validate against known types.
		valid := false
		for _, known := range all {
			if t == known {
				valid = true
				break
			}
		}
		if valid {
			seen[t] = true
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return all
	}
	return result
}

// Ensure context import is used.
var _ = context.Background
