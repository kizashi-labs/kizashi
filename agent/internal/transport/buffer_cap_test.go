package transport

import "testing"

// TestRingBuffer_CapEnforcedUnderFlood guards the disk-spool bound. Before the fix,
// Write() dropped only ONE oldest segment per call, so under sustained pressure with
// variable-size segments `used` overshot maxBytes badly (~10x over a small cap during
// a flood — surfaced by deploy/robustness/run-robustness.sh `spool`). Write() now
// drops oldest in a loop until the new entry fits, so BytesUsed never exceeds the cap
// (for entries smaller than the cap) and the buffer keeps accepting new events
// (drop-oldest, never the run1-style "full → stop writing" stall).
func TestRingBuffer_CapEnforcedUnderFlood(t *testing.T) {
	const capMB = 1
	const maxBytes = int64(capMB) << 20

	rb, err := NewRingBuffer(t.TempDir(), capMB)
	if err != nil {
		t.Fatalf("NewRingBuffer: %v", err)
	}

	blk := make([]byte, 100*1024) // 100 KB < cap, so used must stay <= cap after each write
	for i := 0; i < 50; i++ {     // 50 * 100KB = ~5MB written into a 1MB buffer
		for j := range blk {
			blk[j] = byte('A' + i%26)
		}
		if err := rb.Write(blk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if used := rb.BytesUsed(); used > maxBytes {
			t.Fatalf("after write %d, BytesUsed=%d exceeds cap %d (cap not enforced)", i, used, maxBytes)
		}
	}

	// Flooded ~5MB through a 1MB cap → drops happened, but the buffer is neither
	// empty (still buffering) nor unbounded.
	if n := rb.Len(); n == 0 || int64(n)*int64(len(blk)) > maxBytes+(100*1024) {
		t.Fatalf("Len=%d not consistent with a bounded ~1MB buffer", n)
	}

	// The buffer must keep accepting writes after reaching the cap (no stall).
	before := rb.Len()
	if err := rb.Write([]byte("post-cap entry")); err != nil {
		t.Fatalf("write after cap reached failed (stall?): %v", err)
	}
	if rb.Len() < 1 || rb.BytesUsed() > maxBytes {
		t.Fatalf("post-cap write broke invariants: Len=%d used=%d (before=%d)", rb.Len(), rb.BytesUsed(), before)
	}
}

// TestRingBuffer_FileCountCap guards the segment-COUNT bound. The byte cap alone does
// not limit file count: a long disconnect writing many small batches accumulates one
// file each, bloating the ext4 directory inode (run1: 71k files → ~17MB inode). Write()
// drops oldest when the count reaches maxFiles, independent of bytes.
func TestRingBuffer_FileCountCap(t *testing.T) {
	rb, err := NewRingBuffer(t.TempDir(), 100) // generous byte cap so only the file cap bites
	if err != nil {
		t.Fatalf("NewRingBuffer: %v", err)
	}
	rb.maxFiles = 5 // white-box override for a fast test

	for i := 0; i < 50; i++ {
		if err := rb.Write([]byte("tiny")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if n := rb.Len(); n > 5 {
			t.Fatalf("after write %d, Len=%d exceeds maxFiles=5 (count cap not enforced)", i, n)
		}
	}
	if rb.Len() != 5 {
		t.Fatalf("Len=%d, want 5 (steady state at file cap)", rb.Len())
	}
}

// TestRingBuffer_ShrinkOnDrain verifies the directory is recreated (inode reset) once
// the buffer fully drains after having grown large — healing the run1-style bloat.
func TestRingBuffer_ShrinkOnDrain(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 100)
	if err != nil {
		t.Fatalf("NewRingBuffer: %v", err)
	}
	rb.shrinkAt = 3 // white-box: trigger shrink after a small peak

	for i := 0; i < 5; i++ {
		if err := rb.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if rb.peakFiles < 3 {
		t.Fatalf("peakFiles=%d, expected >=3", rb.peakFiles)
	}
	rb.Ack(5) // drain to empty → should trigger shrink

	if rb.head != 0 || rb.tail != 0 || rb.BytesUsed() != 0 || rb.peakFiles != 0 {
		t.Fatalf("after drain+shrink: head=%d tail=%d used=%d peak=%d, want all 0",
			rb.head, rb.tail, rb.BytesUsed(), rb.peakFiles)
	}
	// Directory still usable after recreation: a fresh write/read round-trips.
	if err := rb.Write([]byte("post-shrink")); err != nil {
		t.Fatalf("write after shrink failed: %v", err)
	}
	if rb.Len() != 1 {
		t.Fatalf("Len=%d after post-shrink write, want 1", rb.Len())
	}
}

// TestRingBuffer_OversizedEntry verifies an entry larger than the whole cap still
// gets written (it empties the buffer first); the next write reclaims it.
func TestRingBuffer_OversizedEntry(t *testing.T) {
	rb, err := NewRingBuffer(t.TempDir(), 1) // 1 MB
	if err != nil {
		t.Fatalf("NewRingBuffer: %v", err)
	}
	if err := rb.Write(make([]byte, 200*1024)); err != nil { // small primer
		t.Fatalf("primer write: %v", err)
	}
	big := make([]byte, 2*1024*1024) // 2MB > 1MB cap
	if err := rb.Write(big); err != nil {
		t.Fatalf("oversized write should succeed (empties then writes): %v", err)
	}
	if rb.Len() != 1 {
		t.Fatalf("after oversized write Len=%d, want 1 (older entry dropped)", rb.Len())
	}
}
