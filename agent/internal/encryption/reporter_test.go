package encryption

import (
	"encoding/json"
	"testing"
)

// TestStatusJSONContract locks the wire format the server's
// /agents/:id/encryption/report handler binds to (encrypted/method/details).
func TestStatusJSONContract(t *testing.T) {
	b, err := json.Marshal(Status{Encrypted: true, Method: "LUKS", Details: "dm-0"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["encrypted"] != true {
		t.Errorf("encrypted field missing/wrong: %v", m["encrypted"])
	}
	if m["method"] != "LUKS" {
		t.Errorf("method field missing/wrong: %v", m["method"])
	}
	if m["details"] != "dm-0" {
		t.Errorf("details field missing/wrong: %v", m["details"])
	}
}

// TestProbeDoesNotPanic ensures the platform probe returns a populated Status
// (a method label is always set) without panicking, whatever the host lacks.
func TestProbeDoesNotPanic(t *testing.T) {
	s := Probe()
	if s.Method == "" {
		t.Errorf("Probe returned empty Method: %+v", s)
	}
}

// TestNewReporter checks the constructor wires its fields.
func TestNewReporter(t *testing.T) {
	r := NewReporter("http://localhost:8080", "agent-1", 0)
	if r == nil || r.client == nil {
		t.Fatal("NewReporter returned incomplete Reporter")
	}
	if r.serverURL != "http://localhost:8080" || r.agentID != "agent-1" {
		t.Errorf("fields not set: %+v", r)
	}
}
