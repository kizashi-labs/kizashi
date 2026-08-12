//go:build linux

package linux

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/edr-platform/agent/internal/ja3"
)

// buildClientHelloBytes constructs a minimal TLS ClientHello record with the given
// ciphers and an SNI, for feeding the parser end-to-end.
func buildClientHelloBytes(sni string, ciphers ...uint16) []byte {
	be16 := func(b []byte, v uint16) []byte {
		var t [2]byte
		binary.BigEndian.PutUint16(t[:], v)
		return append(b, t[:]...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	cs := []byte{}
	for _, c := range ciphers {
		cs = be16(cs, c)
	}
	body = be16(body, uint16(len(cs)))
	body = append(body, cs...)
	body = append(body, 0x01, 0x00)
	// server_name extension.
	name := []byte(sni)
	sniData := be16([]byte{}, uint16(len(name)+3))
	sniData = append(sniData, 0x00)
	sniData = be16(sniData, uint16(len(name)))
	sniData = append(sniData, name...)
	exts := be16([]byte{}, 0)
	exts = be16(exts, uint16(len(sniData)))
	exts = append(exts, sniData...)
	body = be16(body, uint16(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 0x03, 0x01}
	rec = be16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// makeTLSEventRaw builds a struct-tls_event byte buffer as the eBPF program would emit,
// matching the offsets in tls_ebpf_parse.go.
func makeTLSEventRaw(dir uint8, pid uint32, comm, dstIP4 string, dstPort uint16, data []byte) []byte {
	raw := make([]byte, teDataOff+teCapLen)
	raw[teAFOff] = tlsAFInet
	raw[teDirOff] = dir
	binary.NativeEndian.PutUint16(raw[teDstPortOff:], dstPort)
	// dst_ip4 in network byte order (as skc_daddr is).
	parts := strings.Split(dstIP4, ".")
	for i := 0; i < 4 && i < len(parts); i++ {
		var b byte
		for _, ch := range parts[i] {
			b = b*10 + byte(ch-'0')
		}
		raw[teDstIP4Off+i] = b
	}
	binary.NativeEndian.PutUint32(raw[tePIDOff:], pid)
	binary.NativeEndian.PutUint16(raw[teDataLenOff:], uint16(len(data)))
	copy(raw[teCommOff:teCommOff+16], comm)
	copy(raw[teDataOff:], data)
	return raw
}

// TestParseTLSEvent_ClientHello decodes a ClientHello capture and asserts the tuple,
// process context, and that the captured bytes fingerprint to the expected JA3.
func TestParseTLSEvent_ClientHello(t *testing.T) {
	hello := buildClientHelloBytes("cdn.evil.example", 49195, 49199)
	raw := makeTLSEventRaw(tlsDirClient, 4242, "curl", "203.0.113.9", 443, hello)

	cap, ok := parseTLSEvent(raw)
	if !ok {
		t.Fatal("parseTLSEvent returned ok=false for a valid ClientHello event")
	}
	if cap.DstIP != "203.0.113.9" || cap.DstPort != 443 || cap.PID != 4242 || cap.Comm != "curl" {
		t.Errorf("decoded context wrong: %+v", cap)
	}
	if cap.Direction != tlsDirClient {
		t.Errorf("direction = %d, want client", cap.Direction)
	}

	// The captured bytes must fingerprint identically to the source ClientHello.
	_, wantMD5, err := ja3.FromClientHello(hello)
	if err != nil {
		t.Fatalf("ja3: %v", err)
	}
	batch := buildTLSEvent("agent-1", cap)
	if batch == nil {
		t.Fatal("buildTLSEvent returned nil")
	}
	parts := strings.SplitN(batch.Events[0].GetId(), ":", 3)
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(parts[2]), &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload["ja3"] != wantMD5 {
		t.Errorf("ja3 = %v, want %v", payload["ja3"], wantMD5)
	}
	if payload["sni"] != "cdn.evil.example" {
		t.Errorf("sni = %v, want cdn.evil.example (extracted from ClientHello)", payload["sni"])
	}
	if payload["process_name"] != "curl" {
		t.Errorf("process_name = %v, want curl", payload["process_name"])
	}
}

// TestParseTLSEvent_Rejects covers the reject paths: short buffer, bad direction,
// bad AF, and an out-of-range data_len.
func TestParseTLSEvent_Rejects(t *testing.T) {
	good := makeTLSEventRaw(tlsDirClient, 1, "p", "1.2.3.4", 443, []byte{0x16, 0x03, 0x01, 0x00, 0x00, 0x01})

	// Too short.
	if _, ok := parseTLSEvent(good[:teDataOff-1]); ok {
		t.Error("short buffer should be rejected")
	}
	// Bad direction.
	bad := append([]byte(nil), good...)
	bad[teDirOff] = 9
	if _, ok := parseTLSEvent(bad); ok {
		t.Error("unknown direction should be rejected")
	}
	// Bad address family.
	bad = append([]byte(nil), good...)
	bad[teAFOff] = 99
	if _, ok := parseTLSEvent(bad); ok {
		t.Error("unknown AF should be rejected")
	}
	// data_len larger than capture buffer.
	bad = append([]byte(nil), good...)
	binary.NativeEndian.PutUint16(bad[teDataLenOff:], teCapLen+1)
	if _, ok := parseTLSEvent(bad); ok {
		t.Error("oversized data_len should be rejected")
	}
	// data_len zero.
	bad = append([]byte(nil), good...)
	binary.NativeEndian.PutUint16(bad[teDataLenOff:], 0)
	if _, ok := parseTLSEvent(bad); ok {
		t.Error("zero data_len should be rejected")
	}
}
