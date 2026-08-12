package detection

import (
	"fmt"
	"testing"
	"time"
)

func TestDNSTunnelAggregator_FiresOnManySubdomains(t *testing.T) {
	d := newDNSTunnelAggregator()
	base := time.Unix(1_700_000_000, 0)
	fired := 0
	for i := 0; i < 40; i++ {
		q := fmt.Sprintf("chunk%d.tunnel.attacker.com", i)
		if m := d.Observe("agent1", q, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			fired++
			if m[0].MITRETags[0] != "T1071.004" {
				t.Errorf("expected T1071.004, got %v", m[0].MITRETags)
			}
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 tunneling alert (dedup) after 30+ subdomains, got %d", fired)
	}
}

func TestDNSTunnelAggregator_NoFireOnRepeatedSameHost(t *testing.T) {
	d := newDNSTunnelAggregator()
	base := time.Unix(1_700_000_000, 0)
	// Same handful of hostnames queried many times — normal app behavior.
	hosts := []string{"api.service.com", "cdn.service.com", "auth.service.com"}
	for i := 0; i < 100; i++ {
		q := hosts[i%len(hosts)]
		if m := d.Observe("agent1", q, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("fired on %d repeated queries of 3 hostnames (should not)", i)
		}
	}
}

func TestDNSTunnelAggregator_AllowlistsCDN(t *testing.T) {
	d := newDNSTunnelAggregator()
	base := time.Unix(1_700_000_000, 0)
	// A CDN legitimately spreads over many distinct subdomains — must be allowlisted.
	for i := 0; i < 60; i++ {
		q := fmt.Sprintf("d%dabc.cloudfront.net", i)
		if m := d.Observe("agent1", q, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("fired on CDN (cloudfront.net) — should be allowlisted")
		}
	}
}

func TestDNSTunnelAggregator_WindowExpiry(t *testing.T) {
	d := newDNSTunnelAggregator()
	base := time.Unix(1_700_000_000, 0)
	// 40 distinct subdomains but each > window apart — never accumulates.
	for i := 0; i < 40; i++ {
		q := fmt.Sprintf("s%d.slow.example.org", i)
		at := base.Add(time.Duration(i) * 2 * dnsAggWindow)
		if m := d.Observe("agent1", q, at); len(m) > 0 {
			t.Fatalf("fired on slow spread-out queries (should be windowed out)")
		}
	}
}

func TestRegistrableAndSub(t *testing.T) {
	cases := []struct{ q, reg, sub string }{
		{"chunk1.tunnel.attacker.com", "attacker.com", "chunk1.tunnel"},
		{"example.com", "example.com", ""},
		{"a.b.c.d.evil.net", "evil.net", "a.b.c.d"},

		// 2ラベルの公開接尾辞。ここを末尾2ラベルで切ると、その ccTLD 配下の
		// 全組織が1つのバケットに合流する。FPソークが実際に登録ドメイン
		// "co.jp" として Fast-Flux を報告した。
		{"www.example.co.jp", "example.co.jp", "www"},
		{"example.co.jp", "example.co.jp", ""},
		{"a.b.corp.co.jp", "corp.co.jp", "a.b"},
		{"mail.example.co.uk", "example.co.uk", "mail"},
		{"cdn.shop.com.au", "shop.com.au", "cdn"},
		{"host.example.ne.jp", "example.ne.jp", "host"},
		// 公開接尾辞に見えるが該当しないもの (通常の2ラベル扱い)
		{"www.example.jp", "example.jp", "www"},
		{"api.co.example.com", "example.com", "api.co"},
	}
	for _, c := range cases {
		reg, sub := registrableAndSub(c.q)
		if reg != c.reg || sub != c.sub {
			t.Errorf("registrableAndSub(%q) = (%q,%q), want (%q,%q)", c.q, reg, sub, c.reg, c.sub)
		}
	}
}
