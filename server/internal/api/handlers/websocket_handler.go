package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/wsbus"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// allowedWSOrigins returns the set of permitted WebSocket origins.
// Configure via ALLOWED_ORIGINS env var (comma-separated, e.g. https://app.example.com,https://admin.example.com).
// Defaults to permitting all origins when the variable is unset (development mode).
func allowedWSOrigins() map[string]bool {
	raw := os.Getenv("ALLOWED_ORIGINS")
	if raw == "" {
		return nil // nil means allow all (dev mode)
	}
	set := make(map[string]bool)
	for _, o := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			set[trimmed] = true
		}
	}
	return set
}

var wsAllowedOrigins = allowedWSOrigins()

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		if wsAllowedOrigins == nil {
			// ALLOWED_ORIGINS not set — allow all (development / single-host deployments)
			return true
		}
		origin := r.Header.Get("Origin")
		if wsAllowedOrigins[origin] {
			return true
		}
		slog.Warn("websocket: rejected connection from disallowed origin", "origin", origin)
		return false
	},
}

// wsClientAdapter wraps a gorilla WebSocket connection to satisfy wsbus.Client.
type wsClientAdapter struct {
	conn   *websocket.Conn
	ch     chan []byte
	userID string
	role   string
}

func (c *wsClientAdapter) Send(data []byte) {
	select {
	case c.ch <- data:
	default:
		// Client buffer full — drop message
	}
}

func (c *wsClientAdapter) Role() string { return c.role }

// WebSocketHandler handles WebSocket upgrade and connection lifecycle.
type WebSocketHandler struct{}

// NewWebSocketHandler creates a new WebSocketHandler.
func NewWebSocketHandler() *WebSocketHandler {
	return &WebSocketHandler{}
}

// Handle upgrades the connection and manages the WebSocket lifecycle.
// GET /api/v1/ws
func (h *WebSocketHandler) Handle(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Warn("websocket upgrade failed", "err", err)
		return
	}

	// Extract user info from JWT context (set by auth middleware)
	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")
	userIDStr, _ := userID.(string)
	roleStr, _ := role.(string)

	client := &wsClientAdapter{
		conn:   conn,
		ch:     make(chan []byte, 256),
		userID: userIDStr,
		role:   roleStr,
	}

	hub := wsbus.Global()
	hub.Register(client)
	defer func() {
		hub.Unregister(client)
		conn.Close()
	}()

	slog.Info("websocket client connected", "user_id", userIDStr, "role", roleStr,
		"total_clients", hub.ConnectedCount())

	// Send welcome message
	welcome, _ := json.Marshal(wsbus.Message{
		Type:      "connected",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      json.RawMessage(`{"message":"Connected to EDR real-time feed"}`),
	})
	conn.WriteMessage(websocket.TextMessage, welcome) //nolint:errcheck

	// Writer goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case msg, ok := <-client.ch:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
				if !ok {
					conn.WriteMessage(websocket.CloseMessage, []byte{}) //nolint:errcheck
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	// Reader loop (keep-alive + handle client messages)
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
		return nil
	})
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
