package ingestion

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildEventsInsert_MultiRow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	chunk := []preppedEvent{
		{evtType: "process", evtTime: now, raw: []byte(`{"a":1}`), eventID: "11111111-1111-1111-1111-111111111111"},
		{evtType: "network", evtTime: now, raw: []byte(`{"b":2}`), eventID: "22222222-2222-2222-2222-222222222222"},
		{evtType: "dns", evtTime: now, raw: []byte(`{"c":3}`), eventID: "33333333-3333-3333-3333-333333333333"},
	}
	query, args := buildEventsInsert("agent-1", chunk)

	// 5 params per row → 15 args for 3 rows.
	if len(args) != 15 {
		t.Fatalf("args: want 15, got %d", len(args))
	}
	// Placeholders must be sequential and correctly typed per row.
	for _, want := range []string{
		"($1, $2::uuid, $3, $4::jsonb, $5::uuid)",
		"($6, $7::uuid, $8, $9::jsonb, $10::uuid)",
		"($11, $12::uuid, $13, $14::jsonb, $15::uuid)",
	} {
		if !strings.Contains(query, want) {
			t.Errorf("query missing tuple %q\ngot: %s", want, query)
		}
	}
	// Tuples are comma-joined (one INSERT, not three).
	if strings.Count(query, "INSERT INTO events") != 1 {
		t.Errorf("expected a single INSERT statement, got: %s", query)
	}
	if strings.Count(query, "::jsonb") != 3 {
		t.Errorf("expected 3 jsonb casts, got: %s", query)
	}
	// agent_id is the 2nd arg of every row and identical.
	for _, i := range []int{1, 6, 11} {
		if args[i] != "agent-1" {
			t.Errorf("arg[%d]: want agent-1, got %v", i, args[i])
		}
	}
	// raw payloads preserved in order at the 4th arg of each row.
	if string(args[3].([]byte)) != `{"a":1}` || string(args[13].([]byte)) != `{"c":3}` {
		t.Errorf("raw payloads not bound in order: %v ... %v", args[3], args[13])
	}
	// The event_id must be written explicitly, not left to the column DEFAULT:
	// it is the only identifier the NATS envelope and the stored row share, so an
	// alert can be traced back to its evidence.
	if args[4] != chunk[0].eventID || args[14] != chunk[2].eventID {
		t.Errorf("event_ids not bound in order: %v ... %v", args[4], args[14])
	}
}

func TestBuildEventsInsert_SingleRow(t *testing.T) {
	query, args := buildEventsInsert("a", []preppedEvent{
		{evtType: "process", evtTime: time.Unix(1, 0), raw: []byte(`{}`), eventID: "44444444-4444-4444-4444-444444444444"},
	})
	if len(args) != 5 {
		t.Fatalf("args: want 5, got %d", len(args))
	}
	if !strings.HasSuffix(strings.TrimSpace(query), "($1, $2::uuid, $3, $4::jsonb, $5::uuid)") {
		t.Errorf("unexpected single-row query: %s", query)
	}
	if !strings.Contains(query, "event_id") {
		t.Errorf("event_id column missing from INSERT: %s", query)
	}
}

// The envelope must carry the same events.event_id the row was written with —
// that shared identifier is the whole point, and it is what lets a detection
// record which evidence it fired on.
func TestNormalizedEventCarriesEventID(t *testing.T) {
	ne := NormalizedEvent{
		AgentID: "a1", Type: "process",
		EventID:   "55555555-5555-5555-5555-555555555555",
		Timestamp: time.Unix(1_700_000_000, 0),
		Data:      json.RawMessage(`{}`),
	}
	b, err := json.Marshal(ne)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["event_id"] != ne.EventID {
		t.Errorf("event_id not on the wire: %v", back["event_id"])
	}
	// Producers older than this field omit it; the JSON must stay valid and the
	// consumer must see "" rather than a decode error.
	b2, _ := json.Marshal(NormalizedEvent{AgentID: "a1", Type: "process", Data: json.RawMessage(`{}`)})
	if strings.Contains(string(b2), "event_id") {
		t.Errorf("empty event_id must be omitted, got: %s", b2)
	}
}
