package collector

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The create_remote_thread finding must ride the same "<type>:<uuid>:<json>" ID
// wire format as credential_access so the server's prefix-promotion decodes it
// with no proto change. A malformed ID or payload = the injection event is
// silently dropped, so pin the shape.
func TestBuildRemoteThreadEvent(t *testing.T) {
	batch := BuildRemoteThreadEvent("agent-1", RemoteThreadPayload(
		1234, `C:\Users\victim\AppData\Local\Temp\evil.exe`,
		5678, `C:\Windows\System32\svchost.exe`))
	if batch == nil {
		t.Fatal("BuildRemoteThreadEvent returned nil")
	}
	if batch.GetAgentId() != "agent-1" || len(batch.GetEvents()) != 1 {
		t.Fatalf("unexpected batch: agent=%s events=%d", batch.GetAgentId(), len(batch.GetEvents()))
	}
	evt := batch.GetEvents()[0]
	if evt.GetType() != v1.EventType_EVENT_TYPE_LOG {
		t.Errorf("event type = %v, want LOG", evt.GetType())
	}

	id := evt.GetId()
	if !strings.HasPrefix(id, "create_remote_thread:") {
		t.Fatalf("id must carry the create_remote_thread prefix, got %q", id)
	}
	// Server extracts the 3rd colon-delimited segment as the JSON payload.
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("id must be <type>:<uuid>:<json>, got %q", id)
	}
	var p struct {
		SourcePID   int    `json:"source_pid"`
		SourceImage string `json:"source_image"`
		TargetPID   int    `json:"target_pid"`
		TargetImage string `json:"target_image"`
	}
	if err := json.Unmarshal([]byte(parts[2]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.SourcePID != 1234 || p.TargetPID != 5678 {
		t.Errorf("PIDs not preserved: %+v", p)
	}
	if !strings.Contains(p.SourceImage, "evil.exe") || !strings.HasSuffix(p.TargetImage, `svchost.exe`) {
		t.Errorf("images not preserved: %+v", p)
	}
}
