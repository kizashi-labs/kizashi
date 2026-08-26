package hardening

import (
	"encoding/json"
	"testing"
)

// TestReportJSONContract locks the wire format the server's
// /agents/:id/hardening/report handler binds to.
func TestReportJSONContract(t *testing.T) {
	b, err := json.Marshal(Report{
		Benchmark: "bench",
		Checks:    []Check{{ID: "c1", Title: "t", Passed: true, Details: "d"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["benchmark"] != "bench" {
		t.Errorf("benchmark field wrong: %v", m["benchmark"])
	}
	checks, ok := m["checks"].([]any)
	if !ok || len(checks) != 1 {
		t.Fatalf("checks field wrong: %v", m["checks"])
	}
	c0 := checks[0].(map[string]any)
	if c0["id"] != "c1" || c0["passed"] != true {
		t.Errorf("check fields wrong: %v", c0)
	}
}

// TestAssessProducesChecks ensures the platform assessment returns checks with
// stable IDs and does not panic. (Empty is allowed on unsupported platforms.)
func TestAssessProducesChecks(t *testing.T) {
	checks := Assess()
	for _, c := range checks {
		if c.ID == "" {
			t.Errorf("assessment check has empty ID: %+v", c)
		}
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
