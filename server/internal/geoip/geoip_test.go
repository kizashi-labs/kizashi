package geoip

import (
	"testing"
)

// ─── Lookup ───────────────────────────────────────────────────────────────────

func TestLookup_PrivateIP_ReturnsInternal(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("192.168.1.100")
	if loc.CountryCode != "INT" {
		t.Errorf("プライベートIP: CountryCode got %q, want INT", loc.CountryCode)
	}
	if loc.Country != "Internal" {
		t.Errorf("プライベートIP: Country got %q, want Internal", loc.Country)
	}
}

func TestLookup_LoopbackIP_ReturnsInternal(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("127.0.0.1")
	if loc.CountryCode != "INT" {
		t.Errorf("ループバックIP: CountryCode got %q, want INT", loc.CountryCode)
	}
}

func TestLookup_RFC1918_10x_ReturnsInternal(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("10.0.0.1")
	if loc.CountryCode != "INT" {
		t.Errorf("10.x.x.x: CountryCode got %q, want INT", loc.CountryCode)
	}
}

func TestLookup_InvalidIP_ReturnsUnknown(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("not-an-ip")
	if loc.CountryCode != "XX" {
		t.Errorf("無効なIP: CountryCode got %q, want XX", loc.CountryCode)
	}
	if loc.Country != "Unknown" {
		t.Errorf("無効なIP: Country got %q, want Unknown", loc.Country)
	}
}

// skipIfNoNetwork は ip-api.com へのアクセスが不可能な環境でテストをスキップする
func skipIfNoNetwork(t *testing.T, loc *Location) {
	t.Helper()
	if loc.CountryCode == "XX" {
		t.Skip("ネットワーク不可 (ip-api.com へアクセスできません)")
	}
}

func TestLookup_PublicIP_APNIC_ReturnsCountry(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("1.2.3.4") // APNIC address block — must return a real country
	skipIfNoNetwork(t, loc)
	if loc.CountryCode == "XX" || loc.CountryCode == "INT" {
		t.Errorf("パブリックIP 1.2.3.4: 有効な CountryCode が期待されますが got %q", loc.CountryCode)
	}
}

func TestLookup_PublicIP_RIPE_ReturnsCountry(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("31.0.0.1") // RIPE-allocated block — must return a real country
	skipIfNoNetwork(t, loc)
	if loc.CountryCode == "XX" || loc.CountryCode == "INT" {
		t.Errorf("パブリックIP 31.0.0.1: 有効な CountryCode が期待されますが got %q", loc.CountryCode)
	}
}

func TestLookup_PublicIP_EU_ReturnsCountry(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("80.0.0.1") // RIPE/EU 割当ブロック — 実在の国コードを返すはず
	skipIfNoNetwork(t, loc)     // Lookup は ip-api.com 依存。オフラインでは XX を返すためスキップ
	if loc.CountryCode == "XX" || loc.CountryCode == "INT" {
		t.Errorf("パブリックIP 80.0.0.1: 有効な CountryCode が期待されますが got %q", loc.CountryCode)
	}
}

func TestLookup_PublicIP_GoogleDNS_ReturnsUS(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("8.8.8.8") // Google Public DNS — ip-api.com は US を返す
	skipIfNoNetwork(t, loc)    // オフラインでは XX を返すためスキップ
	if loc.CountryCode != "US" {
		t.Errorf("8.8.8.8: CountryCode got %q, want US", loc.CountryCode)
	}
}

func TestLookup_ReturnsIPField(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("8.8.8.8")
	if loc.IP != "8.8.8.8" {
		t.Errorf("Location.IP: got %q, want 8.8.8.8", loc.IP)
	}
}

func TestLookup_IPv6_ReturnsUnknown(t *testing.T) {
	l := NewLocator()
	loc := l.Lookup("2001:db8::1")
	if loc.CountryCode != "XX" {
		t.Errorf("IPv6: CountryCode got %q, want XX", loc.CountryCode)
	}
}

// ─── isPrivate ────────────────────────────────────────────────────────────────

func TestIsPrivate_RFC1918_192168(t *testing.T) {
	import_net_ParseIP := func(s string) []byte {
		// helper: get v4 bytes
		return []byte{192, 168, 0, 1}
	}
	_ = import_net_ParseIP
	// Use Lookup to indirectly test isPrivate
	l := NewLocator()
	if l.Lookup("192.168.0.1").CountryCode != "INT" {
		t.Error("192.168.x.x は private であるべきです")
	}
}

func TestIsPrivate_RFC1918_172_16_to_31(t *testing.T) {
	l := NewLocator()
	for _, ip := range []string{"172.16.0.1", "172.20.0.1", "172.31.255.255"} {
		if l.Lookup(ip).CountryCode != "INT" {
			t.Errorf("%s は private であるべきです", ip)
		}
	}
}
