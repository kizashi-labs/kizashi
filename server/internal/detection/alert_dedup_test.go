package detection

import (
	"testing"
	"time"
)

// TestIsDuplicateAlert_ChainAlertDedup guards the fix for the 2026-07-20 FP
// measurement finding: a single reg.exe launch produced 4 identical
// "不審なプロセス系統を検出: PowerShell spawned reg.exe" alerts (SOC-facing
// duplication, not a distinct-technique signal). engine.go's ML/behavioral
// chain alert path (processEventData) now calls isDuplicateAlert with the
// same (agentID + "\x00" + title) key the Sigma/typedFindings path already
// used, so a re-asserting identical chain finding collapses to one alert per
// alertDedupWindow. This test exercises isDuplicateAlert directly (the
// primitive both call sites share) rather than standing up a full Engine +
// store/NATS harness for the ML path.
func TestIsDuplicateAlert_ChainAlertDedup(t *testing.T) {
	e := &Engine{alertDedup: make(map[string]time.Time)}

	key := "agent-1" + "\x00" + "不審なプロセス系統を検出: PowerShell spawned reg.exe"

	// First occurrence: not a duplicate, and it must record the key.
	if e.isDuplicateAlert(key) {
		t.Fatalf("first occurrence reported as duplicate")
	}
	// Same (agent, title) re-asserting immediately after (the 4x reg.exe case)
	// must be collapsed.
	if !e.isDuplicateAlert(key) {
		t.Fatalf("re-assertion within the window was NOT deduped — the 4x-identical-alert bug would recur")
	}
	if !e.isDuplicateAlert(key) {
		t.Fatalf("third assertion within the window was NOT deduped")
	}

	// A distinct chain finding for the SAME agent (different title) must still
	// fire — dedup must not blanket-suppress everything from a noisy agent.
	otherKey := "agent-1" + "\x00" + "不審なプロセス系統を検出: PowerShell spawned certutil"
	if e.isDuplicateAlert(otherKey) {
		t.Fatalf("distinct chain finding was wrongly deduped against an unrelated title")
	}

	// The same title on a DIFFERENT agent must also still fire — dedup is
	// per-agent, not global.
	otherAgentKey := "agent-2" + "\x00" + "不審なプロセス系統を検出: PowerShell spawned reg.exe"
	if e.isDuplicateAlert(otherAgentKey) {
		t.Fatalf("same finding on a different agent was wrongly deduped")
	}
}
