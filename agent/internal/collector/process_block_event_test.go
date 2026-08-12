package collector

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildProcessBlockEvent_WireFormat(t *testing.T) {
	payload := ProcessBlockPayload("/tmp/blockme", 4242, "audit", "rule-id-1", "deny mimikatz", "high")
	batch := BuildProcessBlockEvent("agent-xyz", payload)

	if batch == nil {
		t.Fatal("BuildProcessBlockEvent returned nil")
	}
	if batch.AgentId != "agent-xyz" {
		t.Errorf("AgentId = %q, want agent-xyz", batch.AgentId)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("Events len = %d, want 1", len(batch.Events))
	}

	id := batch.Events[0].Id
	if !strings.HasPrefix(id, "process_block:") {
		t.Fatalf("event ID %q missing process_block: prefix", id)
	}

	// Format: "process_block:<uuid>:<json>" — the JSON tail may contain ':'.
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("event ID %q not in 3-part form", id)
	}

	var got blockEventPayload
	if err := json.Unmarshal([]byte(parts[2]), &got); err != nil {
		t.Fatalf("payload JSON did not decode: %v (json=%q)", err, parts[2])
	}
	if got.ProcessName != "/tmp/blockme" || got.PID != 4242 || got.Action != "audit" ||
		got.RuleID != "rule-id-1" || got.RuleName != "deny mimikatz" || got.Severity != "high" {
		t.Errorf("decoded payload mismatch: %+v", got)
	}
}
