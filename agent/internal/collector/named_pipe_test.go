package collector

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The pipe_created finding rides the same "<type>:<uuid>:<json>" ID wire format as
// create_remote_thread / ps_module so the server's prefix-promotion decodes it with
// no proto change. PipeName is the load-bearing field for the Cobalt Strike rule.
func TestBuildNamedPipeEvent(t *testing.T) {
	batch := BuildNamedPipeEvent("agent-1", NamedPipePayload(
		`\msagent_5x`, `C:\Users\victim\AppData\Local\Temp\beacon.exe`, 4321))
	if batch == nil {
		t.Fatal("BuildNamedPipeEvent returned nil")
	}
	if batch.GetAgentId() != "agent-1" || len(batch.GetEvents()) != 1 {
		t.Fatalf("unexpected batch: agent=%s events=%d", batch.GetAgentId(), len(batch.GetEvents()))
	}
	evt := batch.GetEvents()[0]
	if evt.GetType() != v1.EventType_EVENT_TYPE_LOG {
		t.Errorf("event type = %v, want LOG", evt.GetType())
	}

	id := evt.GetId()
	if !strings.HasPrefix(id, "pipe_created:") {
		t.Fatalf("id must carry the pipe_created prefix, got %q", id)
	}
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("id must be <type>:<uuid>:<json>, got %q", id)
	}
	var p struct {
		PipeName string `json:"pipe_name"`
		Image    string `json:"image_path"`
		PID      int    `json:"pid"`
	}
	if err := json.Unmarshal([]byte(parts[2]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.PipeName != `\msagent_5x` {
		t.Errorf("pipe_name not preserved: %q", p.PipeName)
	}
	if p.PID != 4321 || !strings.HasSuffix(p.Image, "beacon.exe") {
		t.Errorf("pid/image not preserved: %+v", p)
	}
}
