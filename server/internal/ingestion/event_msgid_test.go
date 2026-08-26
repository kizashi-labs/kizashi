package ingestion

import (
	"fmt"
	"testing"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestEventMsgID_NoCollisionSameSecond reproduces the silent-drop bug: two
// DISTINCT events in the same wall-clock second, each its own single-event batch
// (idx=0), must get DIFFERENT dedup keys — otherwise JetStream drops the second
// and it reaches storage but never the detection engine (observed live with the
// FIM SHA-256 poller emitting several file events per scan at the same second).
func TestEventMsgID_NoCollisionSameSecond(t *testing.T) {
	ts := timestamppb.New(time.Unix(1_700_000_000, 0))
	a := &v1.Event{Id: `fim_change:11111111-aaaa:{"path":"/home/x/.ssh/authorized_keys"}`, Timestamp: ts, Type: v1.EventType_EVENT_TYPE_FILE}
	b := &v1.Event{Id: `fim_change:22222222-bbbb:{"path":"/etc/ld.so.preload"}`, Timestamp: ts, Type: v1.EventType_EVENT_TYPE_FILE}

	idA := eventMsgID("agent-1", "file", a, 0)
	idB := eventMsgID("agent-1", "file", b, 0)
	if idA == idB {
		t.Fatalf("distinct same-second events collided: %q == %q — the second would be silently deduped by JetStream", idA, idB)
	}
}

// TestEventMsgID_StableAcrossRetransmit guards the OTHER property: a verbatim
// retransmission of the SAME event (same *v1.Event Id) MUST produce the same key
// so genuine agent-replay retries are still deduped within the window.
func TestEventMsgID_StableAcrossRetransmit(t *testing.T) {
	e := &v1.Event{Id: "abc-123", Timestamp: timestamppb.New(time.Unix(1_700_000_000, 0)), Type: v1.EventType_EVENT_TYPE_PROCESS}
	first := eventMsgID("agent-1", "process", e, 0)
	retry := eventMsgID("agent-1", "process", e, 3) // later attempt, different idx
	if first != retry {
		t.Errorf("msgID changed across retransmission of the same event: %q != %q", first, retry)
	}
}

// TestEventMsgID_FallbackNoID keeps the legacy key when an event carries no Id.
func TestEventMsgID_FallbackNoID(t *testing.T) {
	e := &v1.Event{Timestamp: timestamppb.New(time.Unix(1_700_000_000, 0)), Type: v1.EventType_EVENT_TYPE_LOG}
	got := eventMsgID("agent-1", "log", e, 2)
	want := fmt.Sprintf("agent-1-log-%d-2", e.GetTimestamp().GetSeconds())
	if got != want {
		t.Errorf("fallback msgID = %q, want %q", got, want)
	}
}
