package detection

import (
	"fmt"
	"testing"
	"time"
)

func TestFastFlux_ManyIPsManyNetsFires(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)
	// 8 IPs across 8 distinct /16 networks within the window → fast-flux.
	ips := []string{"11.0.0.1", "22.0.0.1", "33.0.0.1", "44.0.0.1", "55.0.0.1", "66.0.0.1", "77.0.0.1", "88.0.0.1"}
	var fired bool
	for i, ip := range ips {
		if m := d.Observe("a1", "evil-rendezvous.net", []string{ip}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			fired = true
			if m[0].RuleType != "heuristic" {
				t.Errorf("RuleType = %q, want heuristic", m[0].RuleType)
			}
		}
	}
	if !fired {
		t.Fatal("8 IPs across 8 networks should trip fast-flux")
	}
}

func TestFastFlux_FewNetworksDoesNotFire(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)
	// 10 IPs but all within TWO /16s (a legitimate multi-homed service) → no fire.
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i%2, i) // 203.0.0.* and 203.0.1.* → 2 nets
		if m := d.Observe("a1", "cdn-lite.example", []string{ip}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("10 IPs in 2 networks must not trip fast-flux (got alert at i=%d)", i)
		}
	}
}

func TestFastFlux_BenignParentSkipped(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)
	ips := []string{"11.1.1.1", "22.2.2.2", "33.3.3.3", "44.4.4.4", "55.5.5.5", "66.6.6.6", "77.7.7.7", "88.8.8.8"}
	for i, ip := range ips {
		// amazonaws.com is in the benign-parent allowlist (S3/CloudFront spread many IPs).
		if m := d.Observe("a1", "assets.amazonaws.com", []string{ip}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("benign CDN parent must be skipped, fired at i=%d", i)
		}
	}
}

func TestFastFlux_WindowExpiry(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)
	ips := []string{"11.0.0.1", "22.0.0.1", "33.0.0.1", "44.0.0.1", "55.0.0.1", "66.0.0.1", "77.0.0.1", "88.0.0.1"}
	// Spread the resolutions so each is > window apart → never accumulates.
	for i, ip := range ips {
		at := base.Add(time.Duration(i) * (fastFluxWindow + time.Minute))
		if m := d.Observe("a1", "slow.example", []string{ip}, at); len(m) > 0 {
			t.Fatalf("IPs spread beyond the window must not accumulate, fired at i=%d", i)
		}
	}
}

func TestFastFlux_CNAMEsIgnored(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)
	// Non-IP answers (CNAMEs) must not count toward the IP set.
	for i := 0; i < 12; i++ {
		if m := d.Observe("a1", "cname-chain.example", []string{"alias.other.example"}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("CNAME answers must not trip fast-flux, fired at i=%d", i)
		}
	}
}
