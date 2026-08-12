package detection

import (
	"testing"
	"time"
)

func TestResolutionLinker_RecordAndLookup(t *testing.T) {
	r := newResolutionLinker()
	base := time.Unix(1_700_000_000, 0)
	r.Record("a1", "evil.example", []string{"203.0.113.9", "203.0.113.10"}, base)

	if d := r.Domain("a1", "203.0.113.9", base.Add(time.Minute)); d != "evil.example" {
		t.Errorf("Domain(203.0.113.9) = %q, want evil.example", d)
	}
	if d := r.Domain("a1", "203.0.113.10", base.Add(time.Minute)); d != "evil.example" {
		t.Errorf("Domain(203.0.113.10) = %q, want evil.example", d)
	}
	// Unknown IP → no link.
	if d := r.Domain("a1", "198.51.100.1", base.Add(time.Minute)); d != "" {
		t.Errorf("unknown IP should have no link, got %q", d)
	}
	// Different agent → no link (per-agent isolation).
	if d := r.Domain("a2", "203.0.113.9", base.Add(time.Minute)); d != "" {
		t.Errorf("cross-agent lookup should not link, got %q", d)
	}
}

func TestResolutionLinker_WindowExpiry(t *testing.T) {
	r := newResolutionLinker()
	base := time.Unix(1_700_000_000, 0)
	r.Record("a1", "evil.example", []string{"203.0.113.9"}, base)
	if d := r.Domain("a1", "203.0.113.9", base.Add(resLinkWindow+time.Minute)); d != "" {
		t.Errorf("expired link should not resolve, got %q", d)
	}
}

// TestCrossAxisBridge exercises the intended end state through the correlator directly:
// a DGA verdict on a domain, then a beacon on the IP that domain resolved to, correlate
// once the IP-axis signal is re-keyed onto the linked domain.
func TestCrossAxisBridge(t *testing.T) {
	c := newC2Correlator()
	r := newResolutionLinker()
	base := time.Unix(1_700_000_000, 0)
	domain := "kq3v9z7x1p.com"
	ip := "203.0.113.9"

	// DNS event: DGA verdict on the domain + record its resolved IP.
	if m := c.ObserveSignal("a1", domain, c2SigDGA, base); len(m) != 0 {
		t.Fatalf("single DGA axis should not correlate yet, got %d", len(m))
	}
	r.Record("a1", domain, []string{ip}, base)

	// Later network event: a beacon to that IP. On the IP target alone it does not
	// correlate, but the bridge re-keys it onto the linked domain → 2 axes there.
	later := base.Add(5 * time.Minute)
	if m := c.ObserveSignal("a1", ip, c2SigBeacon, later); len(m) != 0 {
		t.Fatalf("beacon on IP alone should not correlate, got %d", len(m))
	}
	linked := r.Domain("a1", ip, later)
	if linked != domain {
		t.Fatalf("bridge lookup = %q, want %q", linked, domain)
	}
	m := c.ObserveSignal("a1", linked, c2SigBeacon, later)
	if len(m) != 1 {
		t.Fatalf("DGA(domain) + beacon(resolved IP) should correlate via the bridge, got %d", len(m))
	}
	if m[0].Severity != 9 {
		t.Errorf("cross-axis correlation severity = %d, want 9", m[0].Severity)
	}
}
