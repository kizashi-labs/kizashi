package netparse

import (
	"encoding/binary"
	"testing"

	"github.com/edr-platform/agent/internal/ja3"
)

// buildClientHelloRecord makes a minimal TLS ClientHello record.
func buildClientHelloRecord(ciphers ...uint16) []byte {
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
	body = be16(body, 0)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = be16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// buildIPv4TCP wraps a payload in IPv4 + TCP headers (20 bytes each, no options).
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, proto byte, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	tcp[12] = 5 << 4 // data offset = 5 words (20 bytes)
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	total := 20 + len(tcp)
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[9] = proto
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	return append(ip, tcp...)
}

func TestClientHelloFromIPv4TCP_Extracts(t *testing.T) {
	record := buildClientHelloRecord(49195, 49199)
	pkt := buildIPv4TCP([4]byte{10, 0, 0, 5}, [4]byte{203, 0, 113, 9}, 51000, 443, 6, record)

	tp, ok := ClientHelloFromIPv4TCP(pkt)
	if !ok {
		t.Fatal("expected a ClientHello to be extracted")
	}
	if tp.SrcIP != "10.0.0.5" || tp.DstIP != "203.0.113.9" || tp.DstPort != 443 || tp.SrcPort != 51000 {
		t.Errorf("tuple wrong: %+v", tp)
	}
	// The extracted record must fingerprint identically to the source ClientHello.
	wantStr, _, err := ja3.FromClientHello(record)
	if err != nil {
		t.Fatalf("ja3 on source: %v", err)
	}
	gotStr, _, err := ja3.FromClientHello(tp.Record)
	if err != nil {
		t.Fatalf("ja3 on extracted: %v", err)
	}
	if gotStr != wantStr {
		t.Errorf("extracted record JA3 = %q, want %q", gotStr, wantStr)
	}
}

func TestClientHelloFromIPv4TCP_Rejects(t *testing.T) {
	ch := buildClientHelloRecord(49199)

	// Non-TCP (UDP proto 17).
	if _, ok := ClientHelloFromIPv4TCP(buildIPv4TCP([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 443, 17, ch)); ok {
		t.Error("UDP packet must be rejected")
	}
	// TCP but payload is not a TLS handshake (e.g. HTTP).
	http := []byte("GET / HTTP/1.1\r\n")
	if _, ok := ClientHelloFromIPv4TCP(buildIPv4TCP([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 80, 6, http)); ok {
		t.Error("non-TLS TCP payload must be rejected")
	}
	// TCP TLS but a ServerHello (msg type 2), not a ClientHello.
	sh := append([]byte(nil), ch...)
	// handshake message type is at record offset 5.
	sh[5] = 2
	if _, ok := ClientHelloFromIPv4TCP(buildIPv4TCP([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 443, 6, sh)); ok {
		t.Error("ServerHello must be rejected by the ClientHello extractor")
	}
	// Truncated / non-IPv4.
	if _, ok := ClientHelloFromIPv4TCP([]byte{0x60, 0, 0}); ok {
		t.Error("non-IPv4 / short packet must be rejected")
	}
	if _, ok := ClientHelloFromIPv4TCP(nil); ok {
		t.Error("nil must be rejected")
	}
}
