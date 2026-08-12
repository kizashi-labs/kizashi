package handlers

import (
	"strings"
	"testing"
)

// ─── iocToSTIXPattern ────────────────────────────────────────────────────────

func TestIocToSTIXPattern_IP(t *testing.T) {
	got := iocToSTIXPattern("ip", "192.168.1.1")
	if !strings.Contains(got, "ipv4-addr:value") {
		t.Errorf("iocToSTIXPattern(ip) = %q, want ipv4-addr pattern", got)
	}
	if !strings.Contains(got, "192.168.1.1") {
		t.Errorf("iocToSTIXPattern(ip) should contain value, got %q", got)
	}
}

func TestIocToSTIXPattern_IPv4Alias(t *testing.T) {
	got := iocToSTIXPattern("ipv4", "10.0.0.1")
	if !strings.Contains(got, "ipv4-addr:value") {
		t.Errorf("iocToSTIXPattern(ipv4) = %q, want ipv4-addr pattern", got)
	}
}

func TestIocToSTIXPattern_Domain(t *testing.T) {
	got := iocToSTIXPattern("domain", "evil.example.com")
	if !strings.Contains(got, "domain-name:value") {
		t.Errorf("iocToSTIXPattern(domain) = %q, want domain-name pattern", got)
	}
}

func TestIocToSTIXPattern_URL(t *testing.T) {
	got := iocToSTIXPattern("url", "https://evil.example.com/path")
	if !strings.Contains(got, "url:value") {
		t.Errorf("iocToSTIXPattern(url) = %q, want url pattern", got)
	}
}

func TestIocToSTIXPattern_SHA256(t *testing.T) {
	got := iocToSTIXPattern("sha256", "abc123")
	if !strings.Contains(got, "SHA-256") {
		t.Errorf("iocToSTIXPattern(sha256) = %q, want SHA-256 pattern", got)
	}
}

func TestIocToSTIXPattern_MD5(t *testing.T) {
	got := iocToSTIXPattern("md5", "deadbeef")
	if !strings.Contains(got, "MD5") {
		t.Errorf("iocToSTIXPattern(md5) = %q, want MD5 pattern", got)
	}
}

func TestIocToSTIXPattern_Unknown_UsesArtifact(t *testing.T) {
	got := iocToSTIXPattern("email", "test@example.com")
	if !strings.Contains(got, "artifact:payload_bin") {
		t.Errorf("iocToSTIXPattern(email) = %q, want artifact fallback", got)
	}
}

func TestIocToSTIXPattern_ContainsValue(t *testing.T) {
	val := "malware-c2.example"
	got := iocToSTIXPattern("domain", val)
	if !strings.Contains(got, val) {
		t.Errorf("iocToSTIXPattern result should contain value %q, got %q", val, got)
	}
}
