package store

import (
	"context"
	"encoding/json"
	"testing"
)

// recordingPublisher captures the last NATS publish for assertions.
type recordingPublisher struct {
	subject string
	data    []byte
	err     error
}

func (r *recordingPublisher) Publish(subject string, data []byte) error {
	r.subject = subject
	r.data = data
	return r.err
}

// TestCommandStore_ScanCancel verifies the scan-cancel command publishes to the
// agent's scan subject with the "__cancel__" sentinel target (so the agent
// aborts the in-flight scan instead of starting a new one).
func TestCommandStore_ScanCancel(t *testing.T) {
	pub := &recordingPublisher{}
	// ScanCancel only uses nc; pool is not touched.
	s := &CommandStore{nc: pub}

	if err := s.ScanCancel(context.Background(), "agent-123", "user-9", ""); err != nil {
		t.Fatalf("ScanCancel returned error: %v", err)
	}

	if want := "commands.agent-123.scan"; pub.subject != want {
		t.Errorf("subject = %q, want %q", pub.subject, want)
	}

	var cmd struct {
		AgentID     string `json:"agent_id"`
		ScanType    string `json:"scan_type"`
		Target      string `json:"target"`
		TriggeredBy string `json:"triggered_by"`
	}
	if err := json.Unmarshal(pub.data, &cmd); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if cmd.Target != "__cancel__" {
		t.Errorf("Target = %q, want %q (cancel sentinel)", cmd.Target, "__cancel__")
	}
	if cmd.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want agent-123", cmd.AgentID)
	}
	if cmd.TriggeredBy != "user-9" {
		t.Errorf("TriggeredBy = %q, want user-9", cmd.TriggeredBy)
	}
}
