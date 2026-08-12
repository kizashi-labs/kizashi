package ingestion

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// InMemoryCommandDispatcher queues commands per-agent in memory.
// In production, use NATS JetStream or Redis for persistence across restarts.
type InMemoryCommandDispatcher struct {
	mu     sync.Mutex
	queues map[string][]*Command // agentID → pending commands
}

func NewInMemoryCommandDispatcher() *InMemoryCommandDispatcher {
	return &InMemoryCommandDispatcher{
		queues: make(map[string][]*Command),
	}
}

// Enqueue adds a command to the agent's command queue.
func (d *InMemoryCommandDispatcher) Enqueue(agentID string, cmd *Command) error {
	if agentID == "" {
		return fmt.Errorf("agentID は必須です")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.queues[agentID] = append(d.queues[agentID], cmd)
	return nil
}

// Dequeue returns and removes all pending commands for an agent.
func (d *InMemoryCommandDispatcher) Dequeue(agentID string) ([]*Command, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cmds := d.queues[agentID]
	if len(cmds) == 0 {
		return nil, nil
	}

	d.queues[agentID] = nil
	return cmds, nil
}

// EnqueueIsolate creates and enqueues an isolation command.
func (d *InMemoryCommandDispatcher) EnqueueIsolate(agentID, reason, alertID string, allowedIPs []string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"reason":      reason,
		"alert_id":    alertID,
		"allowed_ips": allowedIPs,
	})
	return d.Enqueue(agentID, &Command{
		ID:       generateCommandID(),
		Type:     "isolate",
		Payload:  payload,
		IssuedAt: time.Now(),
	})
}

// EnqueueKillProcess creates and enqueues a process kill command.
func (d *InMemoryCommandDispatcher) EnqueueKillProcess(agentID string, pid uint32, reason string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"pid":    pid,
		"reason": reason,
	})
	return d.Enqueue(agentID, &Command{
		ID:       generateCommandID(),
		Type:     "kill_process",
		Payload:  payload,
		IssuedAt: time.Now(),
	})
}

// EnqueueQuarantine creates and enqueues a file quarantine command.
func (d *InMemoryCommandDispatcher) EnqueueQuarantine(agentID, path, alertID string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"path":     path,
		"alert_id": alertID,
	})
	return d.Enqueue(agentID, &Command{
		ID:       generateCommandID(),
		Type:     "quarantine_file",
		Payload:  payload,
		IssuedAt: time.Now(),
	})
}

// EnqueueCertRenew creates and enqueues a certificate renewal command.
// The renewal_token is a one-time secret the agent must include in its Enroll
// request (as "renew:<token>") so the server can verify it without the static
// enrollment token.
func (d *InMemoryCommandDispatcher) EnqueueCertRenew(agentID, renewalToken string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"type":          "cert_renew",
		"renewal_token": renewalToken,
	})
	return d.Enqueue(agentID, &Command{
		ID:       generateCommandID(),
		Type:     "cert_renew",
		Payload:  payload,
		IssuedAt: time.Now(),
	})
}

func generateCommandID() string {
	return fmt.Sprintf("cmd-%d", time.Now().UnixNano())
}
