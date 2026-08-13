package collector

import (
	"testing"
	"time"
)

// The production failure: one Windows service install (System 7045) produced
// 5,761 events in 24 hours because the inclusive XPath lower bound re-matched the
// boundary event on every 15-second poll and the emit path did not filter it.
func TestWatermarkSuppressesRematchedBoundaryEvent(t *testing.T) {
	install := time.Unix(1_700_000_000, 0)
	w := NewEventLogWatermark(install.Add(-60 * time.Second))

	// Poll 1: the install is new and must be reported.
	round := w.BeginRound()
	if !w.ShouldEmit(round, install) {
		t.Fatal("the first sighting must be emitted")
	}
	w.Commit(install)

	// Polls 2..N: the query is inclusive so the same event comes back forever.
	// None of them may be emitted again.
	for i := 0; i < 100; i++ {
		round = w.BeginRound()
		if w.ShouldEmit(round, install) {
			t.Fatalf("poll %d re-emitted an already-reported event", i+2)
		}
		w.Commit(time.Time{})
	}

	// A genuinely newer install still gets through.
	second := install.Add(time.Hour)
	round = w.BeginRound()
	if !w.ShouldEmit(round, second) {
		t.Error("a later install must still be emitted")
	}
}

// The query bound must stay inclusive: excluding it at millisecond resolution
// could skip an event sharing the boundary millisecond. Over-fetch, filter later.
func TestWatermarkQueryBoundStaysAtTheEmittedMark(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	w := NewEventLogWatermark(base)
	if !w.QueryFrom().Equal(base) {
		t.Errorf("QueryFrom = %v, want %v", w.QueryFrom(), base)
	}
	w.Commit(base.Add(time.Minute))
	if !w.QueryFrom().Equal(base.Add(time.Minute)) {
		t.Errorf("QueryFrom did not follow the commit: %v", w.QueryFrom())
	}
}

// Every ShouldEmit in a round compares against the SAME snapshot. Advancing
// mid-round would drop a later event whose timestamp precedes an earlier one,
// and the Windows API gives no ordering guarantee within a batch.
func TestWatermarkRoundSnapshotIsStableAcrossOutOfOrderBatches(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	w := NewEventLogWatermark(base)

	round := w.BeginRound()
	newer := base.Add(2 * time.Minute)
	older := base.Add(1 * time.Minute) // still newer than the watermark

	if !w.ShouldEmit(round, newer) {
		t.Fatal("newest-first event must be emitted")
	}
	if !w.ShouldEmit(round, older) {
		t.Error("an out-of-order but still-new event must not be dropped")
	}
	w.Commit(newer)

	if w.ShouldEmit(w.BeginRound(), older) {
		t.Error("after the commit, the older event must not be emitted again")
	}
}

// A parse failure yields a zero timestamp, and a stale batch could carry an older
// one. Neither may move the watermark backwards — that would resend everything in
// between.
func TestWatermarkNeverMovesBackwards(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	w := NewEventLogWatermark(base)
	w.Commit(base.Add(time.Hour))
	mark := w.QueryFrom()

	w.Commit(time.Time{})
	w.Commit(base)
	w.Commit(base.Add(time.Minute))

	if !w.QueryFrom().Equal(mark) {
		t.Errorf("watermark moved backwards: %v, want %v", w.QueryFrom(), mark)
	}
}
