package handlers

import "testing"

// ─── extractIOCFromPattern ───────────────────────────────────────────────────

func TestExtractIOCFromPattern_Domain(t *testing.T) {
	iocType, value, ok := extractIOCFromPattern("[domain-name:value = 'evil.example.com']")
	if !ok {
		t.Fatal("extractIOCFromPattern(domain): ok = false")
	}
	if iocType != "domain" {
		t.Errorf("iocType = %q, want 'domain'", iocType)
	}
	if value != "evil.example.com" {
		t.Errorf("value = %q, want 'evil.example.com'", value)
	}
}

func TestExtractIOCFromPattern_IPv4(t *testing.T) {
	iocType, value, ok := extractIOCFromPattern("[ipv4-addr:value = '192.0.2.1']")
	if !ok {
		t.Fatal("extractIOCFromPattern(ipv4): ok = false")
	}
	if iocType != "ip" {
		t.Errorf("iocType = %q, want 'ip'", iocType)
	}
	if value != "192.0.2.1" {
		t.Errorf("value = %q, want '192.0.2.1'", value)
	}
}

func TestExtractIOCFromPattern_SHA256(t *testing.T) {
	hash := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	pattern := "[file:hashes.'SHA-256' = '" + hash + "']"
	iocType, value, ok := extractIOCFromPattern(pattern)
	if !ok {
		t.Fatal("extractIOCFromPattern(sha256): ok = false")
	}
	// Hash sub-types collapse to the canonical "hash": ioc_entries.type has
	// CHECK (type IN ('hash','ip','domain','url','email')), so returning
	// "sha256" here would make the downstream INSERT fail the constraint.
	if iocType != "hash" {
		t.Errorf("iocType = %q, want 'hash'", iocType)
	}
	if value != hash {
		t.Errorf("value = %q, want hash", value)
	}
}

func TestExtractIOCFromPattern_URL(t *testing.T) {
	iocType, value, ok := extractIOCFromPattern("[url:value = 'https://evil.example.com/path']")
	if !ok {
		t.Fatal("extractIOCFromPattern(url): ok = false")
	}
	if iocType != "url" {
		t.Errorf("iocType = %q, want 'url'", iocType)
	}
	_ = value
}

func TestExtractIOCFromPattern_Unknown_ReturnsFalse(t *testing.T) {
	_, _, ok := extractIOCFromPattern("not a stix pattern")
	if ok {
		t.Error("extractIOCFromPattern(unknown): expected ok = false")
	}
}

func TestExtractIOCFromPattern_Empty_ReturnsFalse(t *testing.T) {
	_, _, ok := extractIOCFromPattern("")
	if ok {
		t.Error("extractIOCFromPattern(''): expected ok = false")
	}
}
