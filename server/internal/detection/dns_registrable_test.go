package detection

import (
	"testing"
	"time"
)

// registrableAndSub keys the per-domain state of BOTH the DNS-tunneling
// aggregator and the fast-flux detector. Getting it wrong does not merely
// mislabel an alert — it pools unrelated organisations into one counter, so the
// thresholds are crossed by aggregate traffic that no single domain produced.
//
// The "last two labels" version did exactly that for every multi-label public
// suffix: www.example.co.jp reduced to "co.jp", so an entire fleet's corp
// traffic shared one bucket. The 2026-08-02 FP soak fired
// "Fast-Flux 'co.jp'" on all 20 simulated hosts — the single largest false
// positive in that run.
func TestRegistrableAndSub_MultiLabelPublicSuffix(t *testing.T) {
	cases := []struct {
		query   string
		wantReg string
		wantSub string
	}{
		// The regression: these must NOT collapse to the public suffix.
		{"dc01.corp.example.co.jp", "example.co.jp", "dc01.corp"},
		{"example.co.jp", "example.co.jp", ""},
		{"www.bbc.co.uk", "bbc.co.uk", "www"},
		{"api.service.com.au", "service.com.au", "api"},
		{"a.b.c.naver.co.kr", "naver.co.kr", "a.b.c"},
		{"host.dept.ac.uk", "dept.ac.uk", "host"},

		// Single-label suffixes keep the old behaviour.
		{"www.google.com", "google.com", "www"},
		{"google.com", "google.com", ""},
		{"a.b.example.org", "example.org", "a.b"},

		// Trailing dot and case are normalised.
		{"WWW.Example.CO.JP.", "example.co.jp", "www"},

		// Reverse-lookup zones are multi-label suffixes too.
		{"1.2.0.192.in-addr.arpa", "192.in-addr.arpa", "1.2.0"},
	}
	for _, c := range cases {
		reg, sub := registrableAndSub(c.query)
		if reg != c.wantReg || sub != c.wantSub {
			t.Errorf("registrableAndSub(%q) = (%q, %q), want (%q, %q)", c.query, reg, sub, c.wantReg, c.wantSub)
		}
	}
}

// Two different organisations under the same multi-label suffix must land in
// different buckets. This is the property whose absence caused the false
// positive; asserting the split names alone would not catch a future change that
// re-collapses them.
func TestRegistrableAndSub_DistinctOrgsDoNotShareABucket(t *testing.T) {
	a, _ := registrableAndSub("mail.alpha.co.jp")
	b, _ := registrableAndSub("mail.beta.co.jp")
	if a == b {
		t.Fatalf("alpha.co.jp and beta.co.jp share the bucket %q — per-domain thresholds would be crossed by unrelated traffic", a)
	}
}

// A name that is nothing but a public suffix has no registrable domain to
// aggregate under, and must not become one.
func TestRegistrableAndSub_BarePublicSuffix(t *testing.T) {
	for _, q := range []string{"co.jp", "co.uk", "com.au"} {
		reg, sub := registrableAndSub(q)
		if sub != "" {
			t.Errorf("registrableAndSub(%q) produced a subdomain %q; a bare public suffix has none", q, sub)
		}
		if reg != q {
			t.Errorf("registrableAndSub(%q) = %q; want the input unchanged", q, reg)
		}
	}
}

// The fast-flux detector must not fire on a fleet's own corp domain just because
// several hosts under it were resolved. Drives the detector end to end with the
// exact shape the soak produced.
func TestFastFlux_CorpSubdomainsDoNotPoolIntoOneBucket(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)

	// Eight distinct corp hosts, each with its own address in its own /16 — the
	// pattern that used to pool into "co.jp" and trip the 8-IP / 5-network gate.
	names := []string{
		"dc01.corp.example.co.jp", "dc02.corp.example.co.jp",
		"fs01.corp.example.co.jp", "sccm01.corp.example.co.jp",
		"wks-101.corp.example.co.jp", "wks-102.corp.example.co.jp",
		"wks-203.corp.example.co.jp", "wks-304.corp.example.co.jp",
	}
	for i, n := range names {
		ip := []string{
			"20.1.0.1", "35.2.0.1", "50.3.0.1", "65.4.0.1",
			"80.5.0.1", "95.6.0.1", "110.7.0.1", "125.8.0.1",
		}[i]
		if m := d.Observe("agent1", n, []string{ip}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("fast-flux fired on benign corp host %q (all share example.co.jp but each resolves to one IP)", n)
		}
	}
}

// The detector must still catch the real thing: ONE name rotating across many
// unrelated networks.
func TestFastFlux_SingleNameRotatingManyNetworksStillFires(t *testing.T) {
	d := newDNSFastFluxDetector()
	base := time.Unix(1_700_000_000, 0)

	ips := []string{
		"20.1.0.1", "35.2.0.1", "50.3.0.1", "65.4.0.1",
		"80.5.0.1", "95.6.0.1", "110.7.0.1", "125.8.0.1",
	}
	var fired bool
	for i, ip := range ips {
		if m := d.Observe("agent1", "rendezvous.evil.example", []string{ip}, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("fast-flux did not fire for one name resolving to 8 IPs across 8 networks")
	}
}
