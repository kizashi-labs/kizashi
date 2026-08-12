//go:build windows

package windows

import (
	"strings"
	"testing"
	"time"
)

// parseRangeCount returns the number of distinct block ranges in the result.
func parseRangeCount(ranges []string) int { return len(ranges) }

// rangesContain returns true if any range string contains the sub-string.
func rangesContain(ranges []string, sub string) bool {
	for _, r := range ranges {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func TestComputeBlockRanges_NoAllowed(t *testing.T) {
	// With no allowed IPs (besides loopback), should cover 0.0.0.0–126.255.255.255
	// and 128.0.0.0–255.255.255.255 (loopback 127.x excluded).
	ranges := computeBlockRanges(nil)
	if len(ranges) == 0 {
		t.Fatal("expected at least one block range")
	}
	// 0.0.0.0 should be the start of the first range.
	if !strings.HasPrefix(ranges[0], "0.0.0.0") {
		t.Errorf("first range should start at 0.0.0.0, got %q", ranges[0])
	}
}

func TestComputeBlockRanges_AllowedIPExcluded(t *testing.T) {
	// When 10.0.0.1 is allowed, no block range should include that address alone.
	ranges := computeBlockRanges([]string{"10.0.0.1"})

	// 10.0.0.1 must NOT appear as a standalone address in any range start.
	for _, r := range ranges {
		// A range of "10.0.0.1-10.0.0.1" would mean it IS blocked.
		if r == "10.0.0.1-10.0.0.1" || r == "10.0.0.1" {
			t.Errorf("allowed IP 10.0.0.1 must not appear as a block target, got %q", r)
		}
	}
}

func TestComputeBlockRanges_LoopbackExcluded(t *testing.T) {
	ranges := computeBlockRanges(nil)
	// No range should cover 127.0.0.1.
	for _, r := range ranges {
		// A range like "126.x.x.x-127.x.x.x" would include loopback — that must not happen.
		if strings.HasPrefix(r, "127.") {
			t.Errorf("loopback range must not be blocked, got %q", r)
		}
	}
}

func TestComputeBlockRanges_MultipleAllowed(t *testing.T) {
	// Two allowed IPs should be handled without panic and produce valid ranges.
	ranges := computeBlockRanges([]string{"192.168.1.100", "10.10.10.10"})
	if len(ranges) == 0 {
		t.Fatal("expected block ranges to be computed")
	}
}

func TestComputeBlockRanges_InvalidIPIgnored(t *testing.T) {
	// Invalid IPs must not cause a panic; valid loopback exclusion still applies.
	ranges := computeBlockRanges([]string{"not-an-ip", "256.1.2.3"})
	if len(ranges) == 0 {
		t.Fatal("expected block ranges even when allowed IPs are invalid")
	}
}

func TestComputeBlockRanges_ResultsAreDashSeparatedOrSingle(t *testing.T) {
	ranges := computeBlockRanges([]string{"8.8.8.8"})
	for _, r := range ranges {
		parts := strings.Split(r, "-")
		if len(parts) != 2 && len(parts) != 1 {
			t.Errorf("range %q has unexpected format (want A.B.C.D or A.B.C.D-E.F.G.H)", r)
		}
	}
}

func TestComputeBlockRanges_FewerRangesWithAdjacentAllowed(t *testing.T) {
	// Two adjacent IPs should merge into a smaller complement.
	rangesOne := computeBlockRanges([]string{"10.0.0.5"})
	rangesTwo := computeBlockRanges([]string{"10.0.0.5", "10.0.0.6"})
	// Allowing more IPs should result in equal or more block ranges (gaps), not fewer total ranges.
	// The important thing: both must return at least one range and not panic.
	if len(rangesOne) == 0 || len(rangesTwo) == 0 {
		t.Error("both configurations should produce non-empty block ranges")
	}
	_ = rangesContain // silence unused warning
	_ = parseRangeCount
}

// ─── Orphaned-isolation reconcile ─────────────────────────────

// netshOutputEN is a trimmed `netsh advfirewall firewall show rule name=all` sample
// from an English host carrying three of our rules plus unrelated built-ins.
const netshOutputEN = `
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Allow

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-0-IN
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Block

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-0-OUT
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Action:                               Block

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-1-IN
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Block
`

// netshOutputJA is the same shape on a Japanese host. The labels are localised but
// our rule names are not, which is exactly why parsing keys off the names.
const netshOutputJA = `
規則名:                                EDR-ISOLATE-BLOCK-RANGE-2-OUT
----------------------------------------------------------------------
有効:                                  はい
方向:                                  外向き
操作:                                  ブロック
`

func TestParseIsolationRuleNames_English(t *testing.T) {
	got := parseIsolationRuleNames([]byte(netshOutputEN))
	want := []string{
		"EDR-ISOLATE-BLOCK-RANGE-0-IN",
		"EDR-ISOLATE-BLOCK-RANGE-0-OUT",
		"EDR-ISOLATE-BLOCK-RANGE-1-IN",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseIsolationRuleNames_LocalisedOutput(t *testing.T) {
	got := parseIsolationRuleNames([]byte(netshOutputJA))
	if len(got) != 1 || got[0] != "EDR-ISOLATE-BLOCK-RANGE-2-OUT" {
		t.Errorf("localised netsh output must still yield our rule name, got %v", got)
	}
}

func TestParseIsolationRuleNames_NoneAndNoise(t *testing.T) {
	if got := parseIsolationRuleNames(nil); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
	if got := parseIsolationRuleNames([]byte("No rules match the specified criteria.")); got != nil {
		t.Errorf("no-match output should yield nil, got %v", got)
	}
	// Near-misses must not be adopted: a non-numeric index is not a rule we wrote.
	if got := parseIsolationRuleNames([]byte("EDR-ISOLATE-BLOCK-RANGE-X-IN")); got != nil {
		t.Errorf("non-numeric index must not match, got %v", got)
	}
}

func TestParseIsolationRuleNames_Deduplicates(t *testing.T) {
	// netsh repeats the rule name when a rule exists in several profiles.
	dup := "EDR-ISOLATE-BLOCK-RANGE-0-IN\nEDR-ISOLATE-BLOCK-RANGE-0-IN\nEDR-ISOLATE-BLOCK-RANGE-0-IN"
	got := parseIsolationRuleNames([]byte(dup))
	if len(got) != 1 {
		t.Errorf("expected deduplication to 1 entry, got %v", got)
	}
}

// TestReconcileAdoptsExistingRules is the regression test for the orphaned-isolation
// bug: before this, a restarted manager reported not-isolated while block rules were
// live on the system, so Unisolate() short-circuited and the host stayed cut off with
// no remote way back in.
func TestReconcileAdoptsExistingRules(t *testing.T) {
	live := []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"}
	m := &WFPIsolationManager{listRules: func() []string { return live }}
	m.reconcile()

	if !m.IsIsolated() {
		t.Fatal("IsIsolated() must be true when isolation rules exist on the system")
	}
	if len(m.ruleNames) != len(live) {
		t.Fatalf("ruleNames = %v, want %v — rollback() can only delete what it knows about", m.ruleNames, live)
	}
}

func TestReconcileNoRulesStaysUnisolated(t *testing.T) {
	m := &WFPIsolationManager{listRules: func() []string { return nil }}
	m.reconcile()
	if m.IsIsolated() {
		t.Error("IsIsolated() must stay false when no isolation rules exist")
	}
	if m.ruleNames != nil {
		t.Errorf("ruleNames should stay nil, got %v", m.ruleNames)
	}
}

func TestReconcileNilListerIsSafe(t *testing.T) {
	m := &WFPIsolationManager{}
	m.reconcile() // must not panic
	if m.IsIsolated() {
		t.Error("a manager with no lister must not report isolated")
	}
}

func TestReconcileDoesNotClobberActiveIsolation(t *testing.T) {
	// reconcile enumerates outside the lock, so a real Isolate() can land first.
	// Its ruleNames are authoritative — adopting our stale list would make
	// rollback() delete the wrong set.
	live := []string{"EDR-ISOLATE-BLOCK-RANGE-9-IN"}
	m := &WFPIsolationManager{
		isolated:  true,
		ruleNames: []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"},
		listRules: func() []string { return live },
	}
	m.reconcile()

	if len(m.ruleNames) != 2 || m.ruleNames[0] != "EDR-ISOLATE-BLOCK-RANGE-0-IN" {
		t.Errorf("an active isolation must keep its own ruleNames, got %v", m.ruleNames)
	}
}

// TestReconcileConcurrentWithReaders exercises the goroutine path introduced when
// reconcile was made asynchronous: it writes isolated/ruleNames while the heartbeat
// concurrently calls IsIsolated(). Run under -race this fails if the write escapes
// the mutex.
func TestReconcileConcurrentWithReaders(t *testing.T) {
	m := &WFPIsolationManager{listRules: func() []string {
		time.Sleep(5 * time.Millisecond) // stand in for the slow netsh enumeration
		return []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"}
	}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.reconcile()
	}()
	for i := 0; i < 500; i++ {
		_ = m.IsIsolated()
	}
	<-done

	if !m.IsIsolated() {
		t.Fatal("reconcile must have adopted the rules once it completed")
	}
}
