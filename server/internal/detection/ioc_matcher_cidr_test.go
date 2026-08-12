package detection

import "testing"

// TestIOCMatcher_CIDR verifies that an "ip" IOC expressed as a CIDR range matches any
// address inside the block by containment, while exact-IP IOCs still match exactly and
// unrelated addresses do not match at all.
func TestIOCMatcher_CIDR(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "cidr1", Type: "ip", Value: "45.142.212.0/24", Description: "ransomware block", Severity: 10},
		{ID: "exact1", Type: "ip", Value: "203.0.113.7", Description: "single bad ip", Severity: 8},
	})

	// An address inside the CIDR block (but not the network address) → match.
	hits := m.CheckEvent(map[string]interface{}{"dst_ip": "45.142.212.199"})
	if len(hits) != 1 || hits[0].IOC.ID != "cidr1" {
		t.Fatalf("expected CIDR containment match on 45.142.212.199, got %+v", hits)
	}
	if hits[0].MatchedOn != "dst_ip" {
		t.Errorf("MatchedOn = %q, want dst_ip", hits[0].MatchedOn)
	}

	// The exact IOC still matches exactly.
	if hits := m.CheckEvent(map[string]interface{}{"dst_ip": "203.0.113.7"}); len(hits) != 1 || hits[0].IOC.ID != "exact1" {
		t.Errorf("exact IP IOC should still match, got %+v", hits)
	}

	// An address outside every block/exact IOC → no match.
	if hits := m.CheckEvent(map[string]interface{}{"dst_ip": "8.8.8.8"}); len(hits) != 0 {
		t.Errorf("unrelated IP must not match, got %+v", hits)
	}

	// A src_ip inside the block is matched too.
	if hits := m.CheckEvent(map[string]interface{}{"src_ip": "45.142.212.1"}); len(hits) != 1 {
		t.Errorf("src_ip inside the CIDR block should match, got %+v", hits)
	}

	// CacheSize counts both the CIDR and the exact IOC.
	if got := m.CacheSize(); got != 2 {
		t.Errorf("CacheSize = %d, want 2 (1 cidr + 1 exact)", got)
	}
}

// TestIOCMatcher_BuiltinCIDR confirms the shipped builtin CIDR IOCs match addresses in
// their blocks (guards against the builtins being dropped or mis-typed).
func TestIOCMatcher_BuiltinCIDR(t *testing.T) {
	m := newMatcherWithRecords(builtinIOCs)
	for _, ip := range []string{"185.220.101.250", "45.142.212.50"} {
		if hits := m.CheckEvent(map[string]interface{}{"dst_ip": ip}); len(hits) == 0 {
			t.Errorf("builtin CIDR IOC should match %s", ip)
		}
	}
}
