package handlers

import "testing"

// ─── vtDetectIOCType ──────────────────────────────────────────────────────────

func TestVtDetectIOCType_IPv4_ReturnsIP(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "192.168.1.1", "10.0.0.1"} {
		got := vtDetectIOCType(ip)
		if got != "ip" {
			t.Errorf("vtDetectIOCType(%q) = %q, want 'ip'", ip, got)
		}
	}
}

func TestVtDetectIOCType_Domain_ReturnsDomain(t *testing.T) {
	for _, d := range []string{"example.com", "malware.evil.org"} {
		got := vtDetectIOCType(d)
		if got != "domain" {
			t.Errorf("vtDetectIOCType(%q) = %q, want 'domain'", d, got)
		}
	}
}

func TestVtDetectIOCType_SHA256_ReturnsHash(t *testing.T) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := vtDetectIOCType(hash)
	if got != "hash" {
		t.Errorf("vtDetectIOCType(sha256) = %q, want 'hash'", got)
	}
}

func TestVtDetectIOCType_MD5_ReturnsHash(t *testing.T) {
	hash := "d41d8cd98f00b204e9800998ecf8427e"
	got := vtDetectIOCType(hash)
	if got != "hash" {
		t.Errorf("vtDetectIOCType(md5) = %q, want 'hash'", got)
	}
}

func TestVtDetectIOCType_URL_ReturnsURL(t *testing.T) {
	url := "https://malware.example.com/payload"
	got := vtDetectIOCType(url)
	if got != "url" {
		t.Errorf("vtDetectIOCType(%q) = %q, want 'url'", url, got)
	}
}

func TestVtDetectIOCType_TrimsWhitespace(t *testing.T) {
	got := vtDetectIOCType("  8.8.8.8  ")
	if got != "ip" {
		t.Errorf("vtDetectIOCType(whitespace-padded ip) = %q, want 'ip'", got)
	}
}
