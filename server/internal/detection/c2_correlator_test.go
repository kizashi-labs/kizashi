package detection

import (
	"testing"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

func TestC2Correlator_TwoSignalsFire(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	dst := "203.0.113.9"

	// First axis alone → no correlation.
	if m := c.ObserveSignal("agent-1", dst, c2SigBeacon, base); len(m) != 0 {
		t.Fatalf("single signal should not correlate, got %d", len(m))
	}
	// Second, DISTINCT axis on the same destination → critical correlation.
	m := c.ObserveSignal("agent-1", dst, c2SigJA3, base.Add(time.Minute))
	if len(m) != 1 {
		t.Fatalf("two distinct signals should correlate, got %d", len(m))
	}
	if m[0].Severity != 9 || m[0].AutoIsolate {
		t.Errorf("2-signal correlation: want sev 9, no auto-isolate; got sev %d isolate %v", m[0].Severity, m[0].AutoIsolate)
	}
	if m[0].RuleType != "correlation" {
		t.Errorf("RuleType = %q, want correlation", m[0].RuleType)
	}
}

func TestC2Correlator_ThirdSignalEscalatesAndIsolates(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	dst := "203.0.113.9"

	c.ObserveSignal("agent-1", dst, c2SigBeacon, base)
	c.ObserveSignal("agent-1", dst, c2SigJA3, base.Add(time.Minute)) // fires at n=2
	m := c.ObserveSignal("agent-1", dst, c2SigThreatIntel, base.Add(2*time.Minute))
	if len(m) != 1 {
		t.Fatalf("third distinct signal should escalate, got %d", len(m))
	}
	if m[0].Severity != 10 || !m[0].AutoIsolate {
		t.Errorf("3-signal correlation: want sev 10 + auto-isolate; got sev %d isolate %v", m[0].Severity, m[0].AutoIsolate)
	}
}

func TestC2Correlator_SameSignalTwiceDoesNotFire(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	dst := "203.0.113.9"
	c.ObserveSignal("agent-1", dst, c2SigBeacon, base)
	// Same axis repeated is not independent confirmation.
	if m := c.ObserveSignal("agent-1", dst, c2SigBeacon, base.Add(time.Minute)); len(m) != 0 {
		t.Errorf("repeat of the same axis must not correlate, got %d", len(m))
	}
}

func TestC2Correlator_DistinctDestinationsIsolated(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	// Beacon on one dest, JA3 on ANOTHER → no correlation (different destinations).
	c.ObserveSignal("agent-1", "203.0.113.9", c2SigBeacon, base)
	if m := c.ObserveSignal("agent-1", "198.51.100.4", c2SigJA3, base.Add(time.Minute)); len(m) != 0 {
		t.Errorf("signals on different destinations must not correlate, got %d", len(m))
	}
}

func TestC2Correlator_WindowExpiry(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	dst := "203.0.113.9"
	c.ObserveSignal("agent-1", dst, c2SigBeacon, base)
	// Second signal arrives AFTER the window → the first has expired, so still n=1.
	if m := c.ObserveSignal("agent-1", dst, c2SigJA3, base.Add(c2Window+time.Minute)); len(m) != 0 {
		t.Errorf("signals outside the window must not correlate, got %d", len(m))
	}
}

// TestClassifyC2Signal_RealEmitters guards against RuleName drift: it classifies matches
// produced by the ACTUAL emitters (beacon ToRuleMatch, JA3 + threat-intel typedFindings),
// so a future rename of any of those strings breaks this test rather than silently
// disabling the correlation.
func TestClassifyC2Signal_RealEmitters(t *testing.T) {
	// Beacon (rules package emitter).
	bm := &detectionrules.BeaconMatch{DstIP: "203.0.113.9", Count: 10, MeanInterval: 60 * time.Second}
	if got := classifyC2Signal(bm.ToRuleMatch()); got != c2SigBeacon {
		t.Errorf("beacon ToRuleMatch classified as %q, want %q", got, c2SigBeacon)
	}

	// JA3 blocklist (typedFindings emitter): a known Cobalt Strike JA3.
	ja3Matches := typedFindings("tls_handshake", map[string]interface{}{
		"dst_ip": "203.0.113.9", "ja3": "72a589da586844d7f0818ce684948eea",
	})
	if !anyClassified(ja3Matches, c2SigJA3) {
		t.Errorf("JA3 typedFindings not classified as %q: %v", c2SigJA3, ruleNames(ja3Matches))
	}

	// Threat-intel (typedFindings emitter).
	tiMatches := typedFindings("network", map[string]interface{}{
		"dst_ip": "203.0.113.9", "threat_intel_matched": true,
	})
	if !anyClassified(tiMatches, c2SigThreatIntel) {
		t.Errorf("threat-intel typedFindings not classified as %q: %v", c2SigThreatIntel, ruleNames(tiMatches))
	}

	// DGA (typedFindings emitter): an algorithmic-looking domain.
	dgaMatches := typedFindings("dns", map[string]interface{}{"query": "kq3v9z7x1p.com"})
	if !anyClassified(dgaMatches, c2SigDGA) {
		t.Errorf("DGA typedFindings not classified as %q: %v", c2SigDGA, ruleNames(dgaMatches))
	}

	// DNS exfil/tunnel (typedFindings emitter): a long high-entropy encoded label.
	tunMatches := typedFindings("dns", map[string]interface{}{
		"query": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4.exfil.example",
	})
	if !anyClassified(tunMatches, c2SigDNSTunnel) {
		t.Errorf("DNS tunnel typedFindings not classified as %q: %v", c2SigDNSTunnel, ruleNames(tunMatches))
	}

	// Fast-flux (DNSFastFluxDetector emitter): 8 IPs across 8 networks.
	ff := newDNSFastFluxDetector()
	fbase := time.Unix(1_700_000_000, 0)
	ffIPs := []string{"11.0.0.1", "22.0.0.1", "33.0.0.1", "44.0.0.1", "55.0.0.1", "66.0.0.1", "77.0.0.1", "88.0.0.1"}
	var ffMatch []*detectionrules.RuleMatch
	for i, ip := range ffIPs {
		if m := ff.Observe("a1", "flux.example", []string{ip}, fbase.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			ffMatch = m
		}
	}
	if !anyClassified(ffMatch, c2SigFastFlux) {
		t.Errorf("fast-flux detector output not classified as %q: %v", c2SigFastFlux, ruleNames(ffMatch))
	}
}

func anyClassified(ms []*detectionrules.RuleMatch, want string) bool {
	for _, m := range ms {
		if classifyC2Signal(m) == want {
			return true
		}
	}
	return false
}

func ruleNames(ms []*detectionrules.RuleMatch) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.RuleName)
	}
	return out
}

func TestClassifyC2Signal(t *testing.T) {
	cases := []struct {
		name string
		m    *detectionrules.RuleMatch
		want string
	}{
		{"beacon", &detectionrules.RuleMatch{RuleName: "C2ビーコン疑い（定期的な外部通信）"}, c2SigBeacon},
		{"ja3", &detectionrules.RuleMatch{RuleName: "C2ツール既知TLSフィンガープリント(JA3)一致: Cobalt Strike Beacon"}, c2SigJA3},
		{"threat_intel", &detectionrules.RuleMatch{RuleName: "脅威インテリジェンス一致", RuleType: "ioc"}, c2SigThreatIntel},
		{"fastflux", &detectionrules.RuleMatch{RuleName: "Fast-Flux DNS（高速循環IPインフラ）"}, c2SigFastFlux},
		{"dga", &detectionrules.RuleMatch{RuleName: "DGA（アルゴリズム生成ドメイン）の疑い"}, c2SigDGA},
		{"dns_tunnel", &detectionrules.RuleMatch{RuleName: "DNSトンネリング（大量ユニークサブドメイン）"}, c2SigDNSTunnel},
		{"unrelated", &detectionrules.RuleMatch{RuleName: "Registry Run Key Persistence"}, ""},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		if got := classifyC2Signal(tc.m); got != tc.want {
			t.Errorf("%s: classifyC2Signal = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestC2Correlator_DomainAxisFires: two DISTINCT DNS axes (DGA + fast-flux) on the same
// registrable domain correlate to a critical alert — the domain-target key space.
func TestC2Correlator_DomainAxisFires(t *testing.T) {
	c := newC2Correlator()
	base := time.Unix(1_700_000_000, 0)
	dom := "kq3v9z7x1p.com"
	if m := c.ObserveSignal("agent-1", dom, c2SigDGA, base); len(m) != 0 {
		t.Fatalf("single DNS axis should not correlate, got %d", len(m))
	}
	m := c.ObserveSignal("agent-1", dom, c2SigFastFlux, base.Add(time.Minute))
	if len(m) != 1 {
		t.Fatalf("DGA + fast-flux on one domain should correlate, got %d", len(m))
	}
	if m[0].Severity != 9 {
		t.Errorf("domain 2-axis correlation severity = %d, want 9", m[0].Severity)
	}
}

// TestC2Correlator_IPAndDomainDoNotCross: an IP axis and a domain axis never correlate
// even with the same string value, because they are routed to disjoint key spaces by the
// engine — here we assert the routing predicate that enforces it.
func TestIsDomainAxisSignal(t *testing.T) {
	domain := []string{c2SigDGA, c2SigFastFlux, c2SigDNSTunnel}
	ipAxis := []string{c2SigBeacon, c2SigJA3, c2SigThreatIntel}
	for _, s := range domain {
		if !isDomainAxisSignal(s) {
			t.Errorf("%s should be a domain-axis signal", s)
		}
	}
	for _, s := range ipAxis {
		if isDomainAxisSignal(s) {
			t.Errorf("%s should NOT be a domain-axis signal", s)
		}
	}
}
