package collector

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The ps_module (PowerShell 4103) finding rides the same "<type>:<uuid>:<json>"
// ID wire format as create_remote_thread so the server's prefix-promotion decodes
// it with no proto change. 4103 Payload/ContextInfo are colon- and newline-heavy,
// so this pins that the JSON survives the server's SplitN(id, ":", 3) extraction.
func TestBuildPSModuleEvent(t *testing.T) {
	payload := "CommandInvocation(Add-Type): \"Add-Type\"\nParameterBinding(Add-Type): name=\"TypeDefinition\"; value=\"...\""
	contextInfo := "Severity = Informational\nHost Name = ConsoleHost\nCommand Name = Add-Type\nUser = CORP\\victim"
	batch := BuildPSModuleEvent("agent-1", PSModulePayload(payload, contextInfo, 4321))
	if batch == nil {
		t.Fatal("BuildPSModuleEvent returned nil")
	}
	if batch.GetAgentId() != "agent-1" || len(batch.GetEvents()) != 1 {
		t.Fatalf("unexpected batch: agent=%s events=%d", batch.GetAgentId(), len(batch.GetEvents()))
	}
	evt := batch.GetEvents()[0]
	if evt.GetType() != v1.EventType_EVENT_TYPE_LOG {
		t.Errorf("event type = %v, want LOG", evt.GetType())
	}

	id := evt.GetId()
	if !strings.HasPrefix(id, "ps_module:") {
		t.Fatalf("id must carry the ps_module prefix, got %q", id)
	}
	// Server extracts the 3rd colon-delimited segment as the JSON payload — the
	// colon-heavy Payload/ContextInfo must stay inside that last segment.
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("id must be <type>:<uuid>:<json>, got %q", id)
	}
	var p struct {
		Payload     string `json:"payload"`
		ContextInfo string `json:"context_info"`
		PID         int    `json:"pid"`
	}
	if err := json.Unmarshal([]byte(parts[2]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.PID != 4321 {
		t.Errorf("pid not preserved: %+v", p)
	}
	if !strings.Contains(p.Payload, "CommandInvocation(Add-Type)") {
		t.Errorf("payload not preserved: %q", p.Payload)
	}
	if !strings.Contains(p.ContextInfo, "Command Name = Add-Type") {
		t.Errorf("context_info not preserved: %q", p.ContextInfo)
	}
}
