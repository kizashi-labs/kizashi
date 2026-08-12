//go:build linux || windows

package main

import (
	"testing"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/scanner"
)

// mf builds a MemoryFinding for the suppressor tests.
func mf(pid int, name, addr string, size uint64) collector.MemoryFinding {
	return collector.MemoryFinding{
		PID: pid, ProcessName: name, Address: addr, Size: size,
		Perms: "RWX", RWX: true, Unbacked: true,
	}
}

// TestMemFindingSuppressorFirstSightOnly locks the core contract: a region is
// reported once, then stays quiet while it persists. This is what makes
// default-ON viable — measured on Windows, an idle powershell.exe's CLR JIT
// regions otherwise re-sent 10 events every 60s cycle (~14,400/day/host).
func TestMemFindingSuppressorFirstSightOnly(t *testing.T) {
	s := newMemFindingSuppressor()
	cycle := []collector.MemoryFinding{
		mf(100, "powershell.exe", "a-b", 8192),
		mf(100, "powershell.exe", "c-d", 65536),
	}

	fresh, suppressed := s.filter(cycle)
	if len(fresh) != 2 || suppressed != 0 {
		t.Fatalf("first cycle: fresh=%d suppressed=%d, want 2/0", len(fresh), suppressed)
	}
	// Same regions still present: nothing new to say.
	for i := 0; i < 3; i++ {
		fresh, suppressed = s.filter(cycle)
		if len(fresh) != 0 || suppressed != 2 {
			t.Fatalf("cycle %d: fresh=%d suppressed=%d, want 0/2", i+2, len(fresh), suppressed)
		}
	}
}

// TestMemFindingSuppressorReportsChange verifies detection is not weakened: a
// newly appearing region — which is what injected code looks like — is reported
// even while other regions are being suppressed.
func TestMemFindingSuppressorReportsChange(t *testing.T) {
	s := newMemFindingSuppressor()
	base := mf(100, "powershell.exe", "a-b", 8192)
	s.filter([]collector.MemoryFinding{base})

	injected := mf(100, "powershell.exe", "dead-beef", 4096)
	fresh, suppressed := s.filter([]collector.MemoryFinding{base, injected})
	if len(fresh) != 1 || fresh[0].Address != "dead-beef" || suppressed != 1 {
		t.Fatalf("new region: fresh=%v suppressed=%d, want the injected region only", fresh, suppressed)
	}

	// A region that grows, changes protection, or starts matching a curated rule
	// is new information, not a duplicate.
	grown := base
	grown.Size = 1 << 20
	yaraHit := base
	yaraHit.YARAMatched = true
	for _, c := range []struct {
		name string
		f    collector.MemoryFinding
	}{{"size change", grown}, {"yara hit", yaraHit}} {
		s2 := newMemFindingSuppressor()
		s2.filter([]collector.MemoryFinding{base})
		if fresh, _ := s2.filter([]collector.MemoryFinding{c.f}); len(fresh) != 1 {
			t.Errorf("%s: want re-report, got %d fresh", c.name, len(fresh))
		}
	}
}

// TestMemFindingSuppressorForgetsVanished asserts a region that disappears is
// forgotten, so its reappearance alerts again (allocate → free → re-allocate is a
// real injection pattern), and that exited processes do not accumulate in the
// tracked set.
func TestMemFindingSuppressorForgetsVanished(t *testing.T) {
	s := newMemFindingSuppressor()
	f := mf(100, "powershell.exe", "a-b", 8192)

	s.filter([]collector.MemoryFinding{f})
	s.filter(nil) // region gone (or process exited)
	if len(s.seen) != 0 {
		t.Errorf("tracked set not pruned: %d entries remain", len(s.seen))
	}
	if fresh, _ := s.filter([]collector.MemoryFinding{f}); len(fresh) != 1 {
		t.Errorf("reappearing region should alert again, got %d fresh", len(fresh))
	}
}

// TestMemFindingSuppressorPIDReuse ensures a recycled PID cannot inherit the
// previous process's suppression state and thereby hide its regions.
func TestMemFindingSuppressorPIDReuse(t *testing.T) {
	s := newMemFindingSuppressor()
	s.filter([]collector.MemoryFinding{mf(100, "powershell.exe", "a-b", 8192)})

	reused := mf(100, "evil.exe", "a-b", 8192) // same PID and range, different image
	if fresh, _ := s.filter([]collector.MemoryFinding{reused}); len(fresh) != 1 {
		t.Errorf("reused PID with a different image must alert, got %d fresh", len(fresh))
	}
}

// TestMemoryScanEnabled locks the opt-out gate: memory scanning defaults ON
// (empty/unset) and is disabled only by an explicit off token, while the legacy
// "1" still enables.
func TestMemoryScanEnabled(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"", true},     // unset/empty → default ON
		{"1", true},    // legacy explicit enable
		{"true", true}, // any non-off value → ON
		{"0", false},   // explicit opt-out
		{"false", false},
		{"no", false},
		{"off", false},
		{"OFF", false}, // case-insensitive
		{" 0 ", false}, // trimmed
	}
	for _, c := range cases {
		t.Setenv("EDR_MEMORY_SCAN", c.val)
		if got := memoryScanEnabled(); got != c.want {
			t.Errorf("EDR_MEMORY_SCAN=%q: memoryScanEnabled()=%v, want %v", c.val, got, c.want)
		}
	}
}

// TestMemoryYARARules verifies the curated in-memory ruleset compiles/loads and
// that each distinctive implant / post-exploitation marker matches its rule,
// while benign text — including a single mention of a shared API name gated by a
// "2 of them" condition — does not.
func TestMemoryYARARules(t *testing.T) {
	ys := scanner.NewYARAScanner()
	if err := ys.LoadRules(memoryYARARules); err != nil {
		t.Fatalf("curated in-memory ruleset failed to load: %v", err)
	}

	hits := func(data string) map[string]bool {
		out := map[string]bool{}
		for _, m := range ys.ScanBytes([]byte(data)) {
			out[m.RuleName] = true
		}
		return out
	}

	positive := map[string]string{
		"staging via ReflectiveLoader and beacon.x64.dll": "InMemory_CobaltStrike_Beacon",
		"sekurlsa::logonpasswords":                        "InMemory_Mimikatz",
		"amsiInitFailed field patched":                    "InMemory_AMSI_Bypass",
		"asreproast against the domain":                   "InMemory_Kerberos_Abuse",
		"SharpHound AD collector running":                 "InMemory_SharpHound",
		"loading Demon.x64.dll via KaynLdr":               "InMemory_Havoc_Demon",
		"core_channel_open stdapi_railgun_api":            "InMemory_Meterpreter",
		"marker in_memory_implant_test present":           "InMemory_Test_Implant",
	}
	for data, want := range positive {
		if !hits(data)[want] {
			t.Errorf("data %q: expected rule %q to match, got %v", data, want, hits(data))
		}
	}

	// Benign text with only generic API/word mentions must not match (the rules
	// deliberately avoid single shared strings like "AmsiScanBuffer" / "Rubeus").
	negative := []string{
		"a normal application with no implant markers",
		"this software legitimately calls AmsiScanBuffer once",
		"Rubeus is the name of a jazz band",
	}
	for _, benign := range negative {
		if got := hits(benign); len(got) > 0 {
			t.Errorf("benign %q unexpectedly matched %v", benign, got)
		}
	}
}
