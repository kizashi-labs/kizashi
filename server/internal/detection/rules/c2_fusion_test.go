package rules

import "testing"

func beaconMatch() *BeaconMatch {
	return &BeaconMatch{AgentID: "agent-1", DstIP: "203.0.113.10", Count: 12, JitterCV: 0.1}
}

// TestFusion_BeaconOnly_StaysMedium verifies the no-regression property: a periodic
// beacon whose destination has NO threat-intel match is the unchanged medium alert.
func TestFusion_BeaconOnly_StaysMedium(t *testing.T) {
	s := NewC2FusionScorer()
	m := s.Fuse(beaconMatch())
	if m.Severity != 7 {
		t.Fatalf("beacon-only should stay medium sev7, got %d", m.Severity)
	}
	if m.Title != "[BEHAVIORAL] C2ビーコン疑い（定期的な外部通信）" {
		t.Fatalf("beacon-only title should be unchanged, got %q", m.Title)
	}
}

// TestFusion_BeaconPlusTI_EscalatesCritical verifies S1+S2 fusion: a periodic beacon to a
// destination previously seen as known-malicious escalates to critical.
func TestFusion_BeaconPlusTI_EscalatesCritical(t *testing.T) {
	s := NewC2FusionScorer()
	// S2: the destination was TI-matched on an earlier connection.
	s.ObserveTI("agent-1", "203.0.113.10", TISignal{Matched: true, Category: "c2", Source: "abuse.ch"})

	m := s.Fuse(beaconMatch())
	if m.Severity != 9 {
		t.Fatalf("beacon+TI should escalate to critical sev9, got %d", m.Severity)
	}
	if m.Title == "[BEHAVIORAL] C2ビーコン疑い（定期的な外部通信）" {
		t.Fatalf("beacon+TI title should be escalated, got unchanged %q", m.Title)
	}
	// MITRE tags from the beacon are preserved.
	if len(m.MITRETags) == 0 {
		t.Fatalf("fused alert must keep the beacon's MITRE tags")
	}
}

// TestFusion_TIForDifferentDest_NoEscalation ensures TI on a DIFFERENT destination does
// not bleed into an unrelated beacon (per-destination keying).
func TestFusion_TIForDifferentDest_NoEscalation(t *testing.T) {
	s := NewC2FusionScorer()
	s.ObserveTI("agent-1", "198.51.100.5", TISignal{Matched: true, Category: "c2"})
	m := s.Fuse(beaconMatch()) // beacon is to 203.0.113.10, not the TI-flagged 198.51.100.5
	if m.Severity != 7 {
		t.Fatalf("TI on a different destination must not escalate, got sev %d", m.Severity)
	}
}

// TestFusion_ObserveTI_IgnoresNonMatches ensures a non-match / empty dst is not stored.
func TestFusion_ObserveTI_IgnoresNonMatches(t *testing.T) {
	s := NewC2FusionScorer()
	s.ObserveTI("agent-1", "203.0.113.10", TISignal{Matched: false, Category: "c2"})
	s.ObserveTI("agent-1", "", TISignal{Matched: true, Category: "c2"})
	if m := s.Fuse(beaconMatch()); m.Severity != 7 {
		t.Fatalf("non-match / empty-dst TI must not escalate, got sev %d", m.Severity)
	}
}

// TestFusion_DGA_EscalatesHigh verifies S4: a beacon to an IP resolved from a DGA-like
// domain escalates to high(8) even without a TI match.
func TestFusion_DGA_EscalatesHigh(t *testing.T) {
	s := NewC2FusionScorer()
	// DNS: the destination IP was returned for a DGA-suspicious query.
	s.ObserveDNS("agent-1", []string{"203.0.113.10"}, true)
	m := s.Fuse(beaconMatch())
	if m.Severity != 8 {
		t.Fatalf("beacon+DGA should escalate to high sev8, got %d", m.Severity)
	}
}

// TestFusion_RareAndRawIP_EscalatesHigh verifies S5+S6: a fleet-rare destination reached
// without any prior DNS resolution (raw IP) escalates to high(8).
func TestFusion_RareAndRawIP_EscalatesHigh(t *testing.T) {
	s := NewC2FusionScorer()
	// S5: only this one agent has contacted the destination (rare).
	s.ObserveNetwork("agent-1", "203.0.113.10")
	// S6 guard: the agent HAS DNS activity (resolved some other domain), but never this IP.
	s.ObserveDNS("agent-1", []string{"198.51.100.20"}, false)
	m := s.Fuse(beaconMatch())
	if m.Severity != 8 {
		t.Fatalf("beacon+rare+raw-IP should escalate to high sev8, got %d", m.Severity)
	}
}

// TestFusion_RawIPWithoutDNSTelemetry_NoEscalation verifies the S6 guard: if the agent has
// no DNS telemetry at all, a raw-IP beacon must NOT escalate (can't conclude "raw").
func TestFusion_RawIPWithoutDNSTelemetry_NoEscalation(t *testing.T) {
	s := NewC2FusionScorer()
	s.ObserveNetwork("agent-1", "203.0.113.10") // rare, but no DNS telemetry for the agent
	m := s.Fuse(beaconMatch())
	if m.Severity != 7 {
		t.Fatalf("rare dst without DNS telemetry must stay medium (S6 unproven), got sev %d", m.Severity)
	}
}

// TestFusion_ResolvedDest_NotRawIP verifies S6 negative: a destination that WAS DNS-resolved
// is not a raw-IP signal, so rarity alone does not escalate.
func TestFusion_ResolvedDest_NotRawIP(t *testing.T) {
	s := NewC2FusionScorer()
	s.ObserveNetwork("agent-1", "203.0.113.10")
	s.ObserveDNS("agent-1", []string{"203.0.113.10"}, false) // resolved via DNS → not raw
	m := s.Fuse(beaconMatch())
	if m.Severity != 7 {
		t.Fatalf("rare-but-DNS-resolved dst must stay medium (S6 false), got sev %d", m.Severity)
	}
}

// TestFusion_TIWinsOverWeakSignals verifies S2 dominance: a TI match yields critical even
// when weaker signals are also present.
func TestFusion_TIWinsOverWeakSignals(t *testing.T) {
	s := NewC2FusionScorer()
	s.ObserveTI("agent-1", "203.0.113.10", TISignal{Matched: true, Category: "c2"})
	s.ObserveDNS("agent-1", []string{"203.0.113.10"}, true)
	if m := s.Fuse(beaconMatch()); m.Severity != 9 {
		t.Fatalf("TI must dominate → critical sev9, got %d", m.Severity)
	}
}

// TestTISignalFromEvent verifies extraction of the S2 signal from a flattened event.
func TestTISignalFromEvent(t *testing.T) {
	ti := tiSignalFromEvent(map[string]interface{}{
		"threat_intel_matched":  true,
		"threat_intel_category": "c2",
		"threat_intel_source":   "otx",
	})
	if !ti.Matched || ti.Category != "c2" || ti.Source != "otx" {
		t.Fatalf("unexpected TI extraction: %+v", ti)
	}
	if tiSignalFromEvent(map[string]interface{}{"threat_intel_matched": false}).Matched {
		t.Fatalf("non-matched event must yield Matched=false")
	}
}
