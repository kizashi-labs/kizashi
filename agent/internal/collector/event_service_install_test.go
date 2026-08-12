package collector

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The service_installed finding rides the same "<type>:<uuid>:<json>" ID wire
// format as pipe_created so the server's prefix-promotion decodes it with no
// proto change and raises T1543.003 for malicious service binaries.
func TestBuildServiceInstallEvent(t *testing.T) {
	batch := BuildServiceInstallEvent("agent-1", ServiceInstallPayload(
		"PSEXESVC", `C:\Windows\Temp\beacon.exe`, "user", "demand", "LocalSystem"))
	if batch == nil {
		t.Fatal("BuildServiceInstallEvent returned nil")
	}
	if batch.GetAgentId() != "agent-1" || len(batch.GetEvents()) != 1 {
		t.Fatalf("unexpected batch: agent=%s events=%d", batch.GetAgentId(), len(batch.GetEvents()))
	}
	evt := batch.GetEvents()[0]
	if evt.GetType() != v1.EventType_EVENT_TYPE_LOG {
		t.Errorf("event type = %v, want LOG", evt.GetType())
	}

	id := evt.GetId()
	if !strings.HasPrefix(id, "service_installed:") {
		t.Fatalf("id must carry the service_installed prefix, got %q", id)
	}
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("id must be <type>:<uuid>:<json>, got %q", id)
	}
	var p struct {
		ServiceName string `json:"service_name"`
		ImagePath   string `json:"image_path"`
		Account     string `json:"account"`
	}
	if err := json.Unmarshal([]byte(parts[2]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.ServiceName != "PSEXESVC" || !strings.Contains(p.ImagePath, "beacon.exe") {
		t.Errorf("fields not preserved: %+v", p)
	}
}
