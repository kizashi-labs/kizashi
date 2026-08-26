// Package wsbus provides a lightweight global WebSocket broadcast hub.
// It lives in its own package to avoid import cycles between detection and handlers.
package wsbus

import (
	"encoding/json"
	"sync"
	"time"
)

// Message is the structure pushed to all WebSocket clients.
type Message struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// Client is a connected WebSocket consumer.
type Client interface {
	// Send queues a raw JSON frame for delivery. Non-blocking; drop on full buffer.
	Send(data []byte)
	// Role returns the authenticated role of the client (e.g. "admin", "analyst").
	Role() string
}

// Hub manages registered clients and broadcasts messages.
type Hub struct {
	mu      sync.RWMutex
	clients map[Client]struct{}
}

var global = &Hub{
	clients: make(map[Client]struct{}),
}

// Global returns the process-wide Hub singleton.
func Global() *Hub {
	return global
}

// Register adds a client to the hub.
func (h *Hub) Register(c Client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

// Unregister removes a client from the hub.
func (h *Hub) Unregister(c Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// ConnectedCount returns the number of active clients.
func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast sends msgType+data to every connected client.
func (h *Hub) Broadcast(msgType string, data any) {
	raw := h.marshal(msgType, data)
	if raw == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		c.Send(raw)
	}
}

// BroadcastToRole sends msgType+data only to clients whose role matches.
// An empty role string targets all clients.
func (h *Hub) BroadcastToRole(role, msgType string, data any) {
	raw := h.marshal(msgType, data)
	if raw == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		if role == "" || c.Role() == role {
			c.Send(raw)
		}
	}
}

func (h *Hub) marshal(msgType string, data any) []byte {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	msg := Message{
		Type:      msgType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      payload,
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return raw
}
