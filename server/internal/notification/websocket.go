package notification

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// WebSocketHub manages SSE client connections and broadcasts real-time
// alert and event updates to connected dashboards.
//
// Uses Server-Sent Events (SSE) instead of WebSocket to avoid external
// dependencies. SSE is sufficient for server→browser push.
type WebSocketHub struct {
	mu             sync.RWMutex
	clients        map[string]*sseClient
	cloudClients   map[string]*sseClient
	billingClients map[string]*sseClient
	nc             *nats.Conn
}

type sseClient struct {
	id      string
	ch      chan []byte
	agentID string // if non-empty, only receives events for this agent
}

func NewWebSocketHub(nc *nats.Conn) *WebSocketHub {
	hub := &WebSocketHub{
		clients:        make(map[string]*sseClient),
		cloudClients:   make(map[string]*sseClient),
		billingClients: make(map[string]*sseClient),
		nc:             nc,
	}
	go hub.subscribeNATS()
	return hub
}

// HandleAlerts streams all alert events to connected browsers.
// GET /ws/alerts  (kept at /ws/alerts for backwards compatibility)
func (h *WebSocketHub) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	h.handleSSE(w, r, "")
}

// HandleAgentEvents streams events for a single agent.
// GET /ws/agents/:id/events
func (h *WebSocketHub) HandleAgentEvents(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	h.handleSSE(w, r, agentID)
}

// HandleCloudEvents streams cloud provider events to connected browsers.
// GET /ws/cloud
func (h *WebSocketHub) HandleCloudEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// CORS is handled by the router-level middleware; do not override here.

	client := &sseClient{
		id: generateWSID(),
		ch: make(chan []byte, 256),
	}

	h.mu.Lock()
	h.cloudClients[client.id] = client
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.cloudClients, client.id)
		h.mu.Unlock()
	}()

	welcome, _ := json.Marshal(map[string]interface{}{
		"type":      "connected",
		"stream":    "cloud",
		"client_id": client.id,
		"timestamp": time.Now(),
	})
	fmt.Fprintf(w, "data: %s\n\n", welcome)
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-client.ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			slog.Debug("クラウドSSEクライアントが切断しました", "client", client.id)
			return
		}
	}
}

func (h *WebSocketHub) handleSSE(w http.ResponseWriter, r *http.Request, agentID string) {
	// Verify the response writer supports streaming (http.Flusher)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// CORS is handled by the router-level middleware; do not override here.

	// Register client
	client := &sseClient{
		id:      generateWSID(),
		ch:      make(chan []byte, 256),
		agentID: agentID,
	}

	h.mu.Lock()
	h.clients[client.id] = client
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, client.id)
		h.mu.Unlock()
	}()

	// Send welcome event
	welcome, _ := json.Marshal(map[string]interface{}{
		"type":      "connected",
		"client_id": client.id,
		"timestamp": time.Now(),
	})
	fmt.Fprintf(w, "data: %s\n\n", welcome)
	flusher.Flush()

	// Heartbeat ticker to keep the connection alive
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-client.ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()

		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			slog.Debug("SSEクライアントが切断しました", "client", client.id)
			return
		}
	}
}

// Broadcast sends a message to all connected SSE clients.
func (h *WebSocketHub) Broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.clients {
		select {
		case client.ch <- data:
		default:
			slog.Debug("SSEクライアントのバッファが満杯です", "client", client.id)
		}
	}
}

// BroadcastCloud sends a message to all cloud event SSE clients.
func (h *WebSocketHub) BroadcastCloud(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.cloudClients {
		select {
		case client.ch <- data:
		default:
			slog.Debug("クラウドSSEクライアントのバッファが満杯です", "client", client.id)
		}
	}
}

// HandleBillingEvents streams Stripe subscription events to admin billing dashboards.
// GET /ws/billing
func (h *WebSocketHub) HandleBillingEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// CORS is handled by the router-level middleware; do not override here.

	client := &sseClient{
		id: generateWSID(),
		ch: make(chan []byte, 256),
	}

	h.mu.Lock()
	h.billingClients[client.id] = client
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.billingClients, client.id)
		h.mu.Unlock()
	}()

	welcome, _ := json.Marshal(map[string]interface{}{
		"type":      "connected",
		"stream":    "billing",
		"client_id": client.id,
		"timestamp": time.Now(),
	})
	fmt.Fprintf(w, "data: %s\n\n", welcome)
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-client.ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			slog.Debug("課金SSEクライアントが切断しました", "client", client.id)
			return
		}
	}
}

// BroadcastBilling sends a billing event to all connected billing SSE clients.
func (h *WebSocketHub) BroadcastBilling(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, client := range h.billingClients {
		select {
		case client.ch <- data:
		default:
			slog.Debug("課金SSEクライアントのバッファが満杯です", "client", client.id)
		}
	}
}

// BroadcastToAgent sends a message only to clients watching a specific agent.
func (h *WebSocketHub) BroadcastToAgent(agentID string, msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.clients {
		if client.agentID != agentID {
			continue
		}
		select {
		case client.ch <- data:
		default:
		}
	}
}

// subscribeNATS listens for alert events on NATS and broadcasts them.
func (h *WebSocketHub) subscribeNATS() {
	if h.nc == nil {
		return
	}

	// Subscribe to all alert topics
	if _, err := h.nc.Subscribe("alerts.>", func(msg *nats.Msg) {
		h.Broadcast(map[string]interface{}{
			"type":  "alert",
			"topic": msg.Subject,
			"data":  json.RawMessage(msg.Data),
			"time":  time.Now(),
		})
	}); err != nil {
		slog.Warn("NATSアラートサブスクリプション失敗", "error", err)
	}

	// Subscribe to billing events → broadcast to billing SSE clients
	if _, err := h.nc.Subscribe("billing.>", func(msg *nats.Msg) {
		h.BroadcastBilling(map[string]interface{}{
			"type":  "billing." + splitSubject(msg.Subject)[1],
			"topic": msg.Subject,
			"data":  json.RawMessage(msg.Data),
			"time":  time.Now(),
		})
	}); err != nil {
		slog.Warn("NATS課金サブスクリプション失敗", "error", err)
	}

	// Subscribe to cloud provider events → broadcast to cloud SSE clients
	if _, err := h.nc.Subscribe("cloud.events.>", func(msg *nats.Msg) {
		h.BroadcastCloud(map[string]interface{}{
			"type":  "cloud_event",
			"topic": msg.Subject,
			"data":  json.RawMessage(msg.Data),
			"time":  time.Now(),
		})
	}); err != nil {
		slog.Warn("NATSクラウドイベントサブスクリプション失敗", "error", err)
	}

	// Subscribe to agent-specific events
	if _, err := h.nc.Subscribe("agent.events.>", func(msg *nats.Msg) {
		parts := splitSubject(msg.Subject)
		if len(parts) < 3 {
			return
		}
		agentID := parts[2]

		h.BroadcastToAgent(agentID, map[string]interface{}{
			"type": "event",
			"data": json.RawMessage(msg.Data),
			"time": time.Now(),
		})
	}); err != nil {
		slog.Warn("NATSエージェントイベントサブスクリプション失敗", "error", err)
	}
}

// generateWSID は SSE クライアントの識別子を返す。
//
// 以前は時刻をナノ秒まで整形しただけだった。クライアントは ID をキーにした
// マップで管理されるため、同一ナノ秒に 2 本接続すると片方が上書きされ、
// 配信を受け取れないまま残り続ける。time.Now() の分解能は環境依存で、
// 分解能の粗いホストではこれが現実的に起こりうる。
//
// 時刻に乱数を足して衝突を実質的に無くす。時刻を残すのは、ログに出た ID から
// 接続時刻を読み取れる利点があるため。
func generateWSID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand が読めないのは異常事態。時刻だけにフォールバックする
		// (従来と同じ挙動) が、ID の一意性は保証されなくなる。
		slog.Warn("SSEクライアントID用の乱数生成に失敗しました", "error", err)
		return formatTime(time.Now())
	}
	return formatTime(time.Now()) + "-" + hex.EncodeToString(b[:])
}

func formatTime(t time.Time) string {
	return t.Format("20060102150405.000000000")
}

func splitSubject(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return parts
}
