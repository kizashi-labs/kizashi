package collector

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// The whole point of this counter is to answer "did the sensor ever produce a
// delete?" — a question the aggregate event count and the server-side database
// both failed to answer. So a delete that is generated must be visible even
// though nothing downstream may ever show it.
func TestFileEmitCountsEveryActionAtTheSensorBoundary(t *testing.T) {
	before := FileEmitSnapshot()
	out := make(chan FileEvent, 8)

	for _, action := range []string{"create", "modify", "delete", "rename"} {
		if !EmitFile(context.Background(), out, FileEvent{Path: "/x", Action: action}, nil) {
			t.Fatalf("%s: expected delivery into an empty buffer", action)
		}
	}

	got := FileEmitSnapshot()
	for _, action := range []string{"create", "modify", "delete", "rename"} {
		if delta := got[action].Generated - before[action].Generated; delta != 1 {
			t.Errorf("%s: generated delta = %d, want 1", action, delta)
		}
		if delta := got[action].Dropped - before[action].Dropped; delta != 0 {
			t.Errorf("%s: dropped delta = %d, want 0", action, delta)
		}
	}
}

// A full queue must show up as Dropped, not as a missing Generated: losing the
// event and never having produced it are different failures with different fixes.
func TestFileEmitCountsDropsSeparately(t *testing.T) {
	before := FileEmitSnapshot()
	full := make(chan FileEvent) // unbuffered, no reader → send always times out

	var dropped atomic.Uint64
	if EmitFile(context.Background(), full, FileEvent{Path: "/x", Action: "delete"}, &dropped) {
		t.Fatal("expected the send to fail against a blocked channel")
	}

	got := FileEmitSnapshot()
	if delta := got["delete"].Generated - before["delete"].Generated; delta != 1 {
		t.Errorf("generated delta = %d, want 1 (the sensor DID produce it)", delta)
	}
	if delta := got["delete"].Dropped - before["delete"].Dropped; delta != 1 {
		t.Errorf("dropped delta = %d, want 1", delta)
	}
}

// An empty action must not be silently discarded from the tally — an unlabelled
// event is itself a finding.
func TestFileEmitUnknownAction(t *testing.T) {
	before := FileEmitSnapshot()
	out := make(chan FileEvent, 1)
	EmitFile(context.Background(), out, FileEvent{Path: "/x"}, nil)
	got := FileEmitSnapshot()
	if delta := got["unknown"].Generated - before["unknown"].Generated; delta != 1 {
		t.Errorf("unknown generated delta = %d, want 1", delta)
	}
}

// The counters are written from every collector goroutine.
func TestFileEmitConcurrent(t *testing.T) {
	before := FileEmitSnapshot()
	out := make(chan FileEvent, 256)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				EmitFile(context.Background(), out, FileEvent{Path: "/x", Action: "modify"}, nil)
				<-out
			}
		}()
	}
	wg.Wait()
	got := FileEmitSnapshot()
	if delta := got["modify"].Generated - before["modify"].Generated; delta != 256 {
		t.Errorf("generated delta = %d, want 256", delta)
	}
}

func TestFileEmitActionsSorted(t *testing.T) {
	out := make(chan FileEvent, 4)
	EmitFile(context.Background(), out, FileEvent{Path: "/x", Action: "rename"}, nil)
	EmitFile(context.Background(), out, FileEvent{Path: "/x", Action: "create"}, nil)
	actions := FileEmitActions()
	for i := 1; i < len(actions); i++ {
		if actions[i-1] > actions[i] {
			t.Fatalf("actions not sorted: %v", actions)
		}
	}
}
