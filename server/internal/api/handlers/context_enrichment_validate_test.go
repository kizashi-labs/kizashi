package handlers

import (
	"context"
	"testing"
)

func TestEnrichIndicator_IPType_ReturnsGeoipSource(t *testing.T) {
	_, source := enrichIndicator(context.Background(), "ip", "8.8.8.8")
	if source != "geoip" {
		t.Errorf("enrichIndicator(ip) source = %q, want \"geoip\"", source)
	}
}

func TestEnrichIndicator_IPAddressType_ReturnsGeoipSource(t *testing.T) {
	_, source := enrichIndicator(context.Background(), "ip_address", "1.1.1.1")
	if source != "geoip" {
		t.Errorf("enrichIndicator(ip_address) source = %q, want \"geoip\"", source)
	}
}

func TestEnrichIndicator_HashType_ReturnsVirusTotalSource(t *testing.T) {
	for _, typ := range []string{"hash", "md5", "sha1", "sha256", "file_hash"} {
		_, source := enrichIndicator(context.Background(), typ, "abc123")
		if source != "virustotal" {
			t.Errorf("enrichIndicator(%q) source = %q, want \"virustotal\"", typ, source)
		}
	}
}

func TestEnrichIndicator_DomainType_ReturnsDNSSource(t *testing.T) {
	for _, typ := range []string{"domain", "hostname"} {
		_, source := enrichIndicator(context.Background(), typ, "example.com")
		if source != "dns" {
			t.Errorf("enrichIndicator(%q) source = %q, want \"dns\"", typ, source)
		}
	}
}

func TestEnrichIndicator_URLType_ReturnsDNSSource(t *testing.T) {
	_, source := enrichIndicator(context.Background(), "url", "https://example.com/path")
	if source != "dns" {
		t.Errorf("enrichIndicator(url with valid host) source = %q, want \"dns\"", source)
	}
}

func TestEnrichIndicator_URLType_InvalidURL_ReturnsInternal(t *testing.T) {
	_, source := enrichIndicator(context.Background(), "url", "not-a-url")
	if source != "internal" {
		t.Errorf("enrichIndicator(url with invalid) source = %q, want \"internal\"", source)
	}
}

func TestEnrichIndicator_UnknownType_ReturnsInternal(t *testing.T) {
	data, source := enrichIndicator(context.Background(), "certificate", "xyz")
	if source != "internal" {
		t.Errorf("unknown type source = %q, want \"internal\"", source)
	}
	if data["status"] != "unknown" {
		t.Errorf("unknown type data[status] = %v, want \"unknown\"", data["status"])
	}
}

func TestEnrichIndicator_TypeCaseInsensitive(t *testing.T) {
	_, src1 := enrichIndicator(context.Background(), "IP", "8.8.8.8")
	_, src2 := enrichIndicator(context.Background(), "ip", "8.8.8.8")
	if src1 != src2 {
		t.Errorf("type matching should be case-insensitive: IP=%q ip=%q", src1, src2)
	}
}
