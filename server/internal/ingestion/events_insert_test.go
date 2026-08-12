package ingestion

import (
	"strings"
	"testing"
	"time"
)

func TestBuildEventsInsert_MultiRow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	chunk := []preppedEvent{
		{evtType: "process", evtTime: now, raw: []byte(`{"a":1}`)},
		{evtType: "network", evtTime: now, raw: []byte(`{"b":2}`)},
		{evtType: "dns", evtTime: now, raw: []byte(`{"c":3}`)},
	}
	query, args := buildEventsInsert("agent-1", chunk)

	// 4 params per row → 12 args for 3 rows.
	if len(args) != 12 {
		t.Fatalf("args: want 12, got %d", len(args))
	}
	// Placeholders must be sequential and correctly typed per row.
	for _, want := range []string{
		"($1, $2::uuid, $3, $4::jsonb)",
		"($5, $6::uuid, $7, $8::jsonb)",
		"($9, $10::uuid, $11, $12::jsonb)",
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
	for _, i := range []int{1, 5, 9} {
		if args[i] != "agent-1" {
			t.Errorf("arg[%d]: want agent-1, got %v", i, args[i])
		}
	}
	// raw payloads preserved in order at the 4th arg of each row.
	if string(args[3].([]byte)) != `{"a":1}` || string(args[11].([]byte)) != `{"c":3}` {
		t.Errorf("raw payloads not bound in order: %v ... %v", args[3], args[11])
	}
}

func TestBuildEventsInsert_SingleRow(t *testing.T) {
	query, args := buildEventsInsert("a", []preppedEvent{
		{evtType: "process", evtTime: time.Unix(1, 0), raw: []byte(`{}`)},
	})
	if len(args) != 4 {
		t.Fatalf("args: want 4, got %d", len(args))
	}
	if !strings.HasSuffix(strings.TrimSpace(query), "($1, $2::uuid, $3, $4::jsonb)") {
		t.Errorf("unexpected single-row query: %s", query)
	}
}
