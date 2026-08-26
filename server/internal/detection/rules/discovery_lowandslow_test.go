package rules

import (
	"strconv"
	"testing"
	"time"
)

// These tests guard the low-and-slow hardening of the discovery-burst rule
// (migration 307). Caldera's realistically-timed reconnaissance spaces discovery
// commands with jitter, so a narrow 60s window never accumulated the distinct-count
// threshold and the technique landed as Telemetry-only. Widening the observation
// window to 10m lets the breadth of distinct recon commands accumulate even when
// spread over minutes, without losing fast-burst detection.

// discoveryRule builds a behavioral rule with an explicit window/threshold so a
// single test can compare the shipped-widened rule (307) against the old narrow one.
func discoveryRule(id, window string, threshold int) *DetectionRule {
	content := "window: " + window + "\n" +
		"threshold: " + strconv.Itoa(threshold) + "\n" +
		"event_type: process\n" +
		"field: processName\n" +
		"value_any: whoami, tasklist, systeminfo, ipconfig, netstat, arp, hostname, nltest, quser, ps, id, ss, uname\n" +
		"distinct: true\n" +
		"distinct_field: processName\n" +
		"group_by: agent_id\n" +
		// cooldown: 0 keeps the test deterministic (re-fire allowed).
		"cooldown: 0"
	return &DetectionRule{ID: id, Name: id, Type: "behavioral", Enabled: true, Severity: 6, Content: content}
}

// feedDiscovery drives observeAt with process events for the given command
// basenames, each stamped at base+offset, and returns the last set of matches.
func feedDiscovery(se *SequenceEngine, agent string, base time.Time, cmds []string, offsets []time.Duration) []*RuleMatch {
	var last []*RuleMatch
	for i, cmd := range cmds {
		evt := map[string]any{"processName": `C:\Windows\System32\` + cmd + ".exe"}
		last = se.observeAt(agent, "process", evt, base.Add(offsets[i]))
	}
	return last
}

// Low-and-slow recon: 5 distinct discovery commands spread one every 2 minutes
// (8 minutes total). The widened 10m rule must fire; the old 60s rule must not.
func TestDiscoveryBurst_LowAndSlow(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cmds := []string{"whoami", "netstat", "arp", "ipconfig", "hostname"}
	offsets := []time.Duration{0, 2 * time.Minute, 4 * time.Minute, 6 * time.Minute, 8 * time.Minute}

	// Widened rule (migration 307): window 10m, threshold 5 → fires on the spread.
	wide := NewSequenceEngine()
	wide.LoadRules([]*DetectionRule{discoveryRule("disc-wide", "10m", 5)})
	if m := feedDiscovery(wide, "agent-1", base, cmds, offsets); len(m) == 0 {
		t.Fatal("低速・分散偵察(2分間隔×5種)で拡張窓(10m/5)の探索バーストが発火しませんでした")
	}

	// Old rule (pre-307): window 60s, threshold 4 → misses the spread entirely,
	// documenting the gap 307 closes.
	narrow := NewSequenceEngine()
	narrow.LoadRules([]*DetectionRule{discoveryRule("disc-narrow", "60s", 4)})
	if m := feedDiscovery(narrow, "agent-2", base, cmds, offsets); len(m) != 0 {
		t.Fatal("旧60s窓が低速偵察で発火してしまいました — テスト前提(60sでは幅が溜まらない)が崩れています")
	}
}

// Fast burst must still fire under the widened rule — widening the window does not
// regress immediate detection of a tight recon burst.
func TestDiscoveryBurst_FastBurstStillFires(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cmds := []string{"whoami", "netstat", "arp", "ipconfig", "hostname"}
	// All five within ~8 seconds.
	offsets := []time.Duration{0, 2 * time.Second, 4 * time.Second, 6 * time.Second, 8 * time.Second}

	wide := NewSequenceEngine()
	wide.LoadRules([]*DetectionRule{discoveryRule("disc-wide", "10m", 5)})
	if m := feedDiscovery(wide, "agent-1", base, cmds, offsets); len(m) == 0 {
		t.Fatal("高速バースト(8秒×5種)で拡張窓の探索バーストが発火しませんでした — 即時検知が退行")
	}
}

// Below-threshold breadth must not fire: only 4 distinct commands over 8 minutes
// stays under the raised threshold of 5, keeping benign light admin activity quiet.
func TestDiscoveryBurst_BelowThresholdNoFire(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cmds := []string{"whoami", "netstat", "arp", "ipconfig"}
	offsets := []time.Duration{0, 2 * time.Minute, 4 * time.Minute, 6 * time.Minute}

	wide := NewSequenceEngine()
	wide.LoadRules([]*DetectionRule{discoveryRule("disc-wide", "10m", 5)})
	if m := feedDiscovery(wide, "agent-1", base, cmds, offsets); len(m) != 0 {
		t.Fatal("4種のみ(閾値5未満)で発火してしまいました — FP抑制の閾値が効いていません")
	}
}
