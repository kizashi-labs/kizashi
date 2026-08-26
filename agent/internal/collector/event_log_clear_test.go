package collector

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The eventlog_cleared finding rides the same "<type>:<uuid>:<json>" ID wire
// format as pipe_created / create_remote_thread so the server's prefix-promotion
// decodes it with no proto change and raises T1070.001.
func TestBuildEventLogClearEvent(t *testing.T) {
	batch := BuildEventLogClearEvent("agent-1", EventLogClearPayload("Security", "attacker", ""))
	if batch == nil {
		t.Fatal("BuildEventLogClearEvent returned nil")
	}
	if batch.GetAgentId() != "agent-1" || len(batch.GetEvents()) != 1 {
		t.Fatalf("unexpected batch: agent=%s events=%d", batch.GetAgentId(), len(batch.GetEvents()))
	}
	evt := batch.GetEvents()[0]
	if evt.GetType() != v1.EventType_EVENT_TYPE_LOG {
		t.Errorf("event type = %v, want LOG", evt.GetType())
	}

	id := evt.GetId()
	if !strings.HasPrefix(id, "eventlog_cleared:") {
		t.Fatalf("id must carry the eventlog_cleared prefix, got %q", id)
	}
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("id must be <type>:<uuid>:<json>, got %q", id)
	}
	var p struct {
		Channel    string `json:"channel"`
		User       string `json:"user"`
		BackupPath string `json:"backup_path"`
	}
	if err := json.Unmarshal([]byte(parts[2]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.Channel != "Security" || p.User != "attacker" {
		t.Errorf("channel/user not preserved: %+v", p)
	}
}
