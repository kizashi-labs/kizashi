package detection

import (
	"strings"
	"testing"
)

// TestJA3BlocklistMatch covers the fingerprint lookup: known C2 hashes match
// case-insensitively; unknown/empty hashes do not.
func TestJA3BlocklistMatch(t *testing.T) {
	// A blocklisted Cobalt Strike JA3 (client).
	if sig, ok := matchJA3("72a589da586844d7f0818ce684948eea"); !ok {
		t.Error("expected Cobalt Strike JA3 to match")
	} else if !strings.Contains(sig.Tool, "Cobalt Strike") {
		t.Errorf("unexpected tool %q", sig.Tool)
	}
	// Case-insensitive + surrounding whitespace.
	if _, ok := matchJA3("  72A589DA586844D7F0818CE684948EEA  "); !ok {
		t.Error("expected case-insensitive/trimmed match")
	}
	// Unknown and empty must not match.
	if _, ok := matchJA3("00000000000000000000000000000000"); ok {
		t.Error("unknown JA3 must not match")
	}
	if _, ok := matchJA3(""); ok {
		t.Error("empty JA3 must not match")
	}
}

// TestJA3FindingViaEnvelope drives the real IO-free detection core (the same path the
// live pipeline uses) with a tls_handshake event and asserts a blocklisted JA3/JA3S
// raises a behavioral C2 finding, while a benign fingerprint stays silent.
func TestJA3FindingViaEnvelope(t *testing.T) {
	hasC2Finding := func(findings []EvalFinding) bool {
		for _, f := range findings {
			if f.Source == "behavioral" && strings.Contains(f.Title, "フィンガープリント") {
				return true
			}
		}
		return false
	}

	// Blocklisted client JA3 (Cobalt Strike) → finding.
	mal := map[string]interface{}{
		"dst_ip": "203.0.113.10",
		"sni":    "cdn.example-evil.com",
		"ja3":    "72a589da586844d7f0818ce684948eea",
	}
	if !hasC2Finding(EvaluateEnvelope("tls_handshake", mal)) {
		t.Error("blocklisted JA3 did not raise a C2 finding")
	}

	// Blocklisted server JA3S (Cobalt Strike team server) → finding.
	malS := map[string]interface{}{
		"dst_ip": "203.0.113.11",
		"ja3s":   "ec74a5c51106f0419184d0dd08fb05bc",
	}
	if !hasC2Finding(EvaluateEnvelope("tls_handshake", malS)) {
		t.Error("blocklisted JA3S did not raise a C2 finding")
	}

	// Benign fingerprint → no finding.
	benign := map[string]interface{}{
		"dst_ip": "198.51.100.5",
		"sni":    "api.github.com",
		"ja3":    "deadbeefdeadbeefdeadbeefdeadbeef",
	}
	if hasC2Finding(EvaluateEnvelope("tls_handshake", benign)) {
		t.Error("benign JA3 should not raise a C2 finding")
	}
}
