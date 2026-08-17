package detection

import (
	"encoding/json"
	"testing"
)

// alerts.event_ids is UUID[]: an absent id must become a nil slice, never a
// one-element slice holding "". A producer older than the envelope's event_id
// field must therefore cost the alert its evidence link, not the whole alert.
func TestEvidenceEventIDs(t *testing.T) {
	if got := evidenceEventIDs(""); got != nil {
		t.Errorf("empty id must produce nil, got %#v", got)
	}
	got := evidenceEventIDs("66666666-6666-6666-6666-666666666666")
	if len(got) != 1 || got[0] != "66666666-6666-6666-6666-666666666666" {
		t.Errorf("unexpected evidence list: %#v", got)
	}
}

// The Engine must decode the envelope's event_id, and must NOT let it reach the
// flat map fed to the matchers: "event_id" is already a detection field name (the
// numeric Windows Event ID), so leaking the envelope's UUID under that key would
// silently break every rule selecting on it.
func TestEventEnvelopeEventIDDecodedButNotFlattened(t *testing.T) {
	raw := []byte(`{
		"agent_id":"a1","hostname":"h1","platform":"windows","type":"process",
		"event_id":"77777777-7777-7777-7777-777777777777",
		"data":{"process":{"pid":42,"event_id":5861}}
	}`)
	var env EventEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.EventID != "77777777-7777-7777-7777-777777777777" {
		t.Fatalf("envelope event_id not decoded: %q", env.EventID)
	}

	flat := env.FlatMap()
	// The payload's own event_id (the Windows Event ID) must survive untouched.
	if got, ok := flat["event_id"]; !ok {
		t.Error("payload event_id missing from the flat map")
	} else if f, _ := got.(float64); f != 5861 {
		t.Errorf("payload event_id was overwritten by the envelope UUID: %#v", got)
	}
}

// An envelope from a producer that predates the field decodes to an empty id and
// yields no evidence list — never an error.
func TestEventEnvelopeWithoutEventID(t *testing.T) {
	var env EventEnvelope
	if err := json.Unmarshal([]byte(`{"agent_id":"a1","type":"process","data":{}}`), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.EventID != "" {
		t.Errorf("want empty event_id, got %q", env.EventID)
	}
	if evidenceEventIDs(env.EventID) != nil {
		t.Error("a missing event_id must not produce an evidence entry")
	}
}
