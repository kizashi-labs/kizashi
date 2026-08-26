package ws

import (
	"encoding/json"
	"strings"
)

// SubscriptionFilter defines what events a client wants to receive.
type SubscriptionFilter struct {
	Types       []string // event types: "alert", "agent", "incident", "audit"
	AgentIDs    []string // filter by specific agent IDs (empty = all)
	Severities  []string // filter by severity
	MinSeverity string   // minimum severity level
}

// EventMessage is a WebSocket message with type and payload.
type EventMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// ParseSubscribeMessage parses a subscribe request from a WebSocket client.
// Format: {"action":"subscribe","filter":{"types":["alert"],"severities":["critical","high"]}}
func ParseSubscribeMessage(data []byte) (*SubscriptionFilter, bool) {
	var msg struct {
		Action string             `json:"action"`
		Filter SubscriptionFilter `json:"filter"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, false
	}
	if msg.Action != "subscribe" {
		return nil, false
	}
	return &msg.Filter, true
}

// MatchesFilter checks if an event matches a subscription filter.
func MatchesFilter(filter *SubscriptionFilter, eventType, agentID, severity string) bool {
	if filter == nil {
		return true
	}
	// Check event type
	if len(filter.Types) > 0 {
		found := false
		for _, t := range filter.Types {
			if t == eventType || t == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Check agent ID
	if len(filter.AgentIDs) > 0 && agentID != "" {
		found := false
		for _, id := range filter.AgentIDs {
			if id == agentID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Check severity
	if len(filter.Severities) > 0 && severity != "" {
		found := false
		for _, s := range filter.Severities {
			if strings.EqualFold(s, severity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
