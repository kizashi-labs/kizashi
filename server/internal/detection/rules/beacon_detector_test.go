package rules

import (
	"testing"
	"time"
)

// feed drives observeAt with a sequence of timestamps (no size telemetry) and returns the
// last match (if any). Size-axis tests use feedSized.
func feed(b *BeaconDetector, agent, dst string, base time.Time, offsets []time.Duration) *BeaconMatch {
	var last *BeaconMatch
	for _, off := range offsets {
		if m := b.observeAt(agent, dst, 0, base.Add(off)); m != nil {
			last = m
		}
	}
	return last
}

// feedSized drives observeAt with per-connection timestamps and byte counts, exercising the
// payload-size regularity axis. sizes must be the same length as offsets.
func feedSized(b *BeaconDetector, agent, dst string, base time.Time, offsets []time.Duration, sizes []uint64) *BeaconMatch {
	var last *BeaconMatch
	for i, off := range offsets {
		if m := b.observeAt(agent, dst, sizes[i], base.Add(off)); m != nil {
			last = m
		}
	}
	return last
}

func evenOffsets(n int, interval time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = time.Duration(i) * interval
	}
	return out
}

// cumOffsets turns a list of inter-arrival gaps (seconds) into cumulative offsets.
func cumOffsets(gapsSec ...int) []time.Duration {
	out := make([]time.Duration, 0, len(gapsSec)+1)
	var acc time.Duration
	out = append(out, 0)
	for _, g := range gapsSec {
		acc += time.Duration(g) * time.Second
		out = append(out, acc)
	}
	return out
}

// TestBeacon_JitteredFires is the core of the harmonic-folding upgrade: a beacon
// with ~25% sleep jitter (Cobalt Strike style) must now fire, where the old raw-CV
// gate (≤15%) missed it.
func TestBeacon_JitteredFires(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// Base period 60s with fixed ±~25% jitter (deterministic, no RNG).
	offs := cumOffsets(58, 72, 45, 63, 55, 68, 50, 61, 57, 66)
	m := feed(b, "agent-1", "203.0.113.7", base, offs)
	if m == nil {
		t.Fatal("jittered ~60s beacon should fire under harmonic folding")
	}
	if m.MeanInterval < 50*time.Second || m.MeanInterval > 70*time.Second {
		t.Errorf("base period = %s, want ~60s", m.MeanInterval)
	}
}

// TestBeacon_MissedCheckinsFires: a clean 60s beacon with several skipped check-ins
// (2×/3× gaps) must fire — folding normalises the gaps so the outliers no longer
// blow up the jitter estimate (the old CV gate rejected these).
func TestBeacon_MissedCheckinsFires(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// 60s cadence with a missed beat (120s) and a double-miss (180s).
	offs := cumOffsets(60, 60, 120, 60, 60, 180, 60, 60, 60)
	m := feed(b, "agent-1", "198.51.100.5", base, offs)
	if m == nil {
		t.Fatal("60s beacon with missed check-ins should fire under folding")
	}
	if m.MissedBeats < 2 {
		t.Errorf("expected ≥2 missed beats folded, got %d", m.MissedBeats)
	}
}

// TestBeacon_RandomStillRejected guards against the folding over-firing: aperiodic
// traffic that shares no base period must NOT be flagged.
func TestBeacon_RandomStillRejected(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	offs := cumOffsets(5, 120, 8, 300, 7, 260, 400, 5, 895, 33)
	if m := feed(b, "agent-1", "203.0.113.9", base, offs); m != nil {
		t.Errorf("aperiodic traffic falsely flagged: %+v", m)
	}
}

func TestBeacon_RegularFires(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// 10 connections exactly 60s apart → perfectly regular beacon.
	m := feed(b, "agent-1", "10.0.0.9", base, evenOffsets(10, 60*time.Second))
	if m == nil {
		t.Fatal("regular 60s beacon did not fire")
	}
	if m.DstIP != "10.0.0.9" || m.Count < 8 {
		t.Errorf("unexpected match: %+v", m)
	}
	if m.MeanInterval < 55*time.Second || m.MeanInterval > 65*time.Second {
		t.Errorf("mean interval = %s, want ~60s", m.MeanInterval)
	}
}

func TestBeacon_JitteryDoesNotFire(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// Highly irregular intervals (5s,120s,8s,300s,…) → high jitter, not a beacon.
	offs := []time.Duration{0, 5 * time.Second, 125 * time.Second, 133 * time.Second,
		433 * time.Second, 440 * time.Second, 700 * time.Second, 1100 * time.Second,
		1105 * time.Second, 2000 * time.Second}
	if m := feed(b, "agent-1", "10.0.0.9", base, offs); m != nil {
		t.Errorf("jittery traffic falsely flagged as beacon: %+v", m)
	}
}

func TestBeacon_TooFewDoesNotFire(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// Only 5 regular connections — below MinEvents(8).
	if m := feed(b, "agent-1", "10.0.0.9", base, evenOffsets(5, 60*time.Second)); m != nil {
		t.Errorf("fired with too few samples: %+v", m)
	}
}

func TestBeacon_FastChatterIgnored(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// Regular but sub-MinInterval (2s) — normal chatter, below the beacon band.
	if m := feed(b, "agent-1", "10.0.0.9", base, evenOffsets(12, 2*time.Second)); m != nil {
		t.Errorf("fast regular chatter flagged as beacon: %+v", m)
	}
}

func TestBeacon_Cooldown(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	if m := feed(b, "agent-1", "10.0.0.9", base, evenOffsets(10, 60*time.Second)); m == nil {
		t.Fatal("expected first beacon to fire")
	}
	// More regular connections immediately after — within cooldown, must not re-fire.
	next := base.Add(10 * 60 * time.Second)
	if m := feed(b, "agent-1", "10.0.0.9", next, evenOffsets(10, 60*time.Second)); m != nil {
		t.Errorf("beacon re-fired within cooldown: %+v", m)
	}
}

func TestBeacon_PerDestinationIsolation(t *testing.T) {
	b := NewBeaconDetector()
	base := time.Unix(1_700_000_000, 0)
	// Regular cadence split across two destinations → neither reaches MinEvents alone.
	for i := 0; i < 10; i++ {
		dst := "10.0.0.9"
		if i%2 == 1 {
			dst = "10.0.0.10"
		}
		if m := b.observeAt("agent-1", dst, 0, base.Add(time.Duration(i)*60*time.Second)); m != nil {
			t.Errorf("fired with only %d samples for a destination", i/2+1)
		}
	}
}

func TestAnalyzeBeacon_Pure(t *testing.T) {
	cfg := DefaultBeaconConfig()
	base := time.Unix(1_700_000_000, 0)
	ts := make([]time.Time, 10)
	for i := range ts {
		ts[i] = base.Add(time.Duration(i) * 90 * time.Second)
	}
	res := analyzeBeacon(ts, cfg)
	if !res.ok {
		t.Fatalf("expected regular series to analyze as beacon (period=%s cv=%.3f)", res.period, res.foldedCV)
	}
	if res.foldedCV > 0.01 {
		t.Errorf("perfectly regular series should have ~0 jitter, got cv=%.3f", res.foldedCV)
	}
}

// heavyJitterGaps sits just past the strict folded-jitter gate (foldedCV ≈ 0.32 >
// MaxJitterCV 0.30) while staying in-band (P=60s) and mostly-periodic (cleanFrac 1.0).
// Exactly 8 events → observeAt assesses once, on the full series. Timing alone must NOT
// fire; the payload-size axis decides.
func heavyJitterGaps() []time.Duration {
	return cumOffsets(39, 81, 39, 81, 39, 81, 60)
}

func constSizes(n int, v uint64) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// TestBeacon_UniformPayloadRelaxesJitter is the core of the payload-size axis: a beacon
// too jittery for the timing gate alone still fires when its bytes_sent are uniform —
// catching heavily-jittered implants that a timing-only detector misses.
func TestBeacon_UniformPayloadRelaxesJitter(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	offs := heavyJitterGaps()

	// Same timing, no size telemetry → must NOT fire (strict gate).
	if m := feed(NewBeaconDetector(), "agent-1", "203.0.113.9", base, offs); m != nil {
		t.Fatalf("heavy-jitter beacon should not fire on timing alone, got period=%s cv=%.3f", m.MeanInterval, m.JitterCV)
	}

	// Same timing, uniform payload → fires via the size-assisted relaxed gate.
	m := feedSized(NewBeaconDetector(), "agent-1", "203.0.113.9", base, offs, constSizes(len(offs), 512))
	if m == nil {
		t.Fatal("heavy-jitter beacon with uniform payload should fire via the size axis")
	}
	if !m.SizeRegular || !m.JitterRelax {
		t.Errorf("expected SizeRegular && JitterRelax, got SizeRegular=%v JitterRelax=%v (payloadCV=%.3f)", m.SizeRegular, m.JitterRelax, m.PayloadCV)
	}
}

// TestBeacon_VariablePayloadNoRelax guards the relaxed gate against exploitation by noisy
// traffic: identical jittery timing but VARIABLE payload sizes must stay non-firing.
func TestBeacon_VariablePayloadNoRelax(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	offs := heavyJitterGaps()
	sizes := []uint64{120, 9000, 300, 15000, 80, 22000, 210, 6000}
	if m := feedSized(NewBeaconDetector(), "agent-1", "203.0.113.9", base, offs, sizes); m != nil {
		t.Fatalf("heavy-jitter beacon with variable payload must not fire, got payloadCV=%.3f", m.PayloadCV)
	}
}

// TestBeacon_UniformPayloadRaisesSeverity: a beacon that already fires on timing gains a
// uniform-payload confirmation → SizeRegular set and the alert escalates to severity 8.
func TestBeacon_UniformPayloadRaisesSeverity(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	offs := evenOffsets(10, 90*time.Second) // clean 90s beacon, fires on timing
	m := feedSized(NewBeaconDetector(), "agent-1", "198.51.100.4", base, offs, constSizes(10, 1024))
	if m == nil {
		t.Fatal("clean beacon with uniform payload should fire")
	}
	if !m.SizeRegular || m.JitterRelax {
		t.Errorf("clean+uniform beacon: want SizeRegular && !JitterRelax, got SizeRegular=%v JitterRelax=%v", m.SizeRegular, m.JitterRelax)
	}
	if sev := m.ToRuleMatch().Severity; sev != 8 {
		t.Errorf("uniform-payload beacon severity = %d, want 8", sev)
	}
}
