package collector

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/edr-platform/agent/internal/ja3"
)

// buildClientHello constructs a minimal TLS ClientHello record for the given ciphers.
func buildClientHello(ciphers ...uint16) []byte {
	be16 := func(b []byte, v uint16) []byte {
		var t [2]byte
		binary.BigEndian.PutUint16(t[:], v)
		return append(b, t[:]...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session id len
	cs := []byte{}
	for _, c := range ciphers {
		cs = be16(cs, c)
	}
	body = be16(body, uint16(len(cs)))
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression
	body = be16(body, 0)            // no extensions
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 0x03, 0x01}
	rec = be16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// TestProcessTLSHandshake exercises the full agent seam: raw ClientHello bytes →
// JA3 computation → emittable tls_handshake event whose payload carries the correct
// JA3 MD5, matching what the ja3 package computes directly.
func TestProcessTLSHandshake(t *testing.T) {
	hello := buildClientHello(49195, 49199)
	wantJA3Str, wantMD5, err := ja3.FromClientHello(hello)
	if err != nil {
		t.Fatalf("ja3.FromClientHello: %v", err)
	}
	if wantJA3Str != "771,49195-49199,,," {
		t.Fatalf("unexpected JA3 string %q", wantJA3Str)
	}

	batch := ProcessTLSHandshake("agent-1", "203.0.113.5", 443, "evil.example", "svchost.exe", 990, hello, nil)
	if batch == nil {
		t.Fatal("ProcessTLSHandshake returned nil for a valid ClientHello")
	}
	if len(batch.Events) != 1 {
		t.Fatalf("want 1 event, got %d", len(batch.Events))
	}

	id := batch.Events[0].GetId()
	if !strings.HasPrefix(id, "tls_handshake:") {
		t.Fatalf("event ID missing tls_handshake prefix: %q", id)
	}
	parts := strings.SplitN(id, ":", 3)
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(parts[2]), &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if payload["ja3"] != wantMD5 {
		t.Errorf("payload ja3 = %v, want %v", payload["ja3"], wantMD5)
	}
	if payload["dst_ip"] != "203.0.113.5" || payload["sni"] != "evil.example" {
		t.Errorf("payload context wrong: %+v", payload)
	}
}

// TestProcessTLSHandshakeNoData returns nil when no handshake bytes are present.
func TestProcessTLSHandshakeNoData(t *testing.T) {
	if b := ProcessTLSHandshake("a", "1.2.3.4", 443, "", "", 0, nil, nil); b != nil {
		t.Error("expected nil event when no handshake bytes supplied")
	}
	// Malformed ClientHello (too short) yields no fingerprint → nil event.
	if b := ProcessTLSHandshake("a", "1.2.3.4", 443, "", "", 0, []byte{22, 3, 1, 0}, nil); b != nil {
		t.Error("expected nil event for malformed ClientHello")
	}
}
