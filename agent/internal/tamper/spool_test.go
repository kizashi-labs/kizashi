package tamper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolRoundTrip(t *testing.T) {
	dir := t.TempDir()

	want := New(TypeAgentKilled, ComponentAgent, false).
		WithTarget(4242).
		WithSignal(9).
		WithExitCode(-1).
		WithReason("シグナルで終了")
	if err := Append(dir, want); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, skipped, err := Drain(dir)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if len(got) != 1 {
		t.Fatalf("drained %d findings, want 1", len(got))
	}
	if got[0] != want {
		t.Errorf("round trip changed the payload:\n got %+v\nwant %+v", got[0], want)
	}

	// Draining must consume: a finding reported twice is a finding an analyst
	// stops trusting.
	again, _, err := Drain(dir)
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second drain returned %d findings, want 0", len(again))
	}
}

func TestDrainOnMissingSpoolIsNotAnError(t *testing.T) {
	got, skipped, err := Drain(t.TempDir())
	if err != nil {
		t.Fatalf("Drain on a missing spool: %v", err)
	}
	if len(got) != 0 || skipped != 0 {
		t.Errorf("got %d findings / %d skipped, want 0/0", len(got), skipped)
	}
}

// A corrupt line must not strand the valid findings sitting next to it, and the
// drain must say how many it dropped — silently discarding them would look
// exactly like "nothing tampered with this host".
func TestDrainSkipsCorruptLinesButKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	if err := Append(dir, New(TypeBinaryModified, ComponentBinary, false).WithPath("/usr/bin/edr-agent")); err != nil {
		t.Fatalf("Append: %v", err)
	}

	path := filepath.Join(dir, SpoolFileName)
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	// One line of garbage, and one well-formed JSON object that is not a finding.
	corrupted := "{not json at all\n" + string(existing) + `{"component":"edr-agent"}` + "\n"
	if err := os.WriteFile(path, []byte(corrupted), 0600); err != nil {
		t.Fatalf("write spool: %v", err)
	}

	got, skipped, err := Drain(dir)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("drained %d findings, want 1 (the valid one)", len(got))
	}
	if got[0].TamperType != TypeBinaryModified {
		t.Errorf("TamperType = %q, want %q", got[0].TamperType, TypeBinaryModified)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (malformed JSON + typeless object)", skipped)
	}
}

// An unbounded on-disk spool is a failure this codebase has already shipped once
// (P5-2). A restart loop must not be able to grow the file without limit, and the
// entries that survive must be the newest — during a loop the most recent death
// is the one that describes the current state.
//
// Tested on the pure function rather than by appending maxSpoolEntries+ findings:
// Append rewrites the whole file each call, so driving the cap through it costs a
// minute of wall clock on Windows for the same assertion. The file path itself is
// covered by the round-trip test above.
func TestEvictOldestKeepsTheNewestWithinCaps(t *testing.T) {
	over := make([]string, 0, maxSpoolEntries+25)
	for i := range maxSpoolEntries + 25 {
		over = append(over, `{"n":`+itoa(i)+`}`)
	}
	got := evictOldest(over)

	if len(got) != maxSpoolEntries {
		t.Fatalf("kept %d entries, want the cap of %d", len(got), maxSpoolEntries)
	}
	if want := `{"n":25}`; got[0] != want {
		t.Errorf("oldest surviving entry = %s, want %s (eviction dropped the wrong end)", got[0], want)
	}
	if want := `{"n":` + itoa(maxSpoolEntries+24) + `}`; got[len(got)-1] != want {
		t.Errorf("newest surviving entry = %s, want %s", got[len(got)-1], want)
	}

	// A single line larger than the byte cap is kept rather than producing an
	// empty spool: one oversized entry still carries more than nothing, and
	// Drain reports it as unparseable if it truly is garbage.
	huge := []string{strings.Repeat("x", maxSpoolBytes*2)}
	if got := evictOldest(huge); len(got) != 1 {
		t.Errorf("evictOldest on one oversized line kept %d, want 1", len(got))
	}
}

// itoa avoids importing strconv for two call sites in a test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// The spool format is one finding per line, so a payload that could embed a
// newline would corrupt every finding after it. json.Marshal escapes them, and
// this pins that: the guard in Append must never be the thing that catches it.
func TestAppendKeepsMultilineReasonOnOneLine(t *testing.T) {
	dir := t.TempDir()
	p := New(TypeConfigModified, ComponentConfig, false).
		WithReason("line one\nline two")
	if err := Append(dir, p); err != nil {
		t.Fatalf("Append: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, SpoolFileName))
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if n := strings.Count(strings.TrimRight(string(raw), "\n"), "\n"); n != 0 {
		t.Fatalf("spool holds %d embedded newlines, want 0", n)
	}

	got, _, err := Drain(dir)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != 1 || got[0].Reason != "line one\nline two" {
		t.Errorf("multi-line reason did not survive: %+v", got)
	}
}
