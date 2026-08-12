package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// be16 appends a big-endian uint16.
func be16(b []byte, v uint16) []byte {
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], v)
	return append(b, t[:]...)
}

// tlsRecord wraps a handshake message (type+body) in record + handshake headers.
func tlsRecord(msgType byte, body []byte) []byte {
	hs := []byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{recordTypeHandshake, 0x03, 0x01}
	rec = be16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func expectMD5(t *testing.T, s, got string) {
	t.Helper()
	sum := md5.Sum([]byte(s))
	if want := hex.EncodeToString(sum[:]); want != got {
		t.Errorf("md5 = %s, want %s (for %q)", got, want, s)
	}
}

// TestFromClientHello builds a ClientHello with GREASE in the ciphers, extensions and
// curves, and asserts JA3 strips GREASE and formats every field per the reference spec.
func TestFromClientHello(t *testing.T) {
	body := []byte{0x03, 0x03}               // client version 771 (TLS 1.2)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len 0

	// Cipher suites: GREASE 0x0a0a + 49195 (0xc02b) + 49199 (0xc02f).
	ciphers := []byte{}
	ciphers = be16(ciphers, 0x0a0a)
	ciphers = be16(ciphers, 49195)
	ciphers = be16(ciphers, 49199)
	body = be16(body, uint16(len(ciphers)))
	body = append(body, ciphers...)

	body = append(body, 0x01, 0x00) // compression: len 1, method 0

	// Extensions.
	exts := []byte{}
	// GREASE extension 0x1a1a, len 0 → stripped.
	exts = be16(exts, 0x1a1a)
	exts = be16(exts, 0)
	// server_name (0), len 0.
	exts = be16(exts, 0)
	exts = be16(exts, 0)
	// supported_groups (10): list-len(2) + GREASE 0x0a0a + 29 (0x001d) + 23 (0x0017).
	grp := []byte{}
	grp = be16(grp, 0x0a0a)
	grp = be16(grp, 29)
	grp = be16(grp, 23)
	grpData := be16([]byte{}, uint16(len(grp)))
	grpData = append(grpData, grp...)
	exts = be16(exts, 10)
	exts = be16(exts, uint16(len(grpData)))
	exts = append(exts, grpData...)
	// ec_point_formats (11): count(1)=1 + format 0.
	pf := []byte{0x01, 0x00}
	exts = be16(exts, 11)
	exts = be16(exts, uint16(len(pf)))
	exts = append(exts, pf...)

	body = be16(body, uint16(len(exts)))
	body = append(body, exts...)

	record := tlsRecord(handshakeClientHello, body)

	ja3, md5hex, err := FromClientHello(record)
	if err != nil {
		t.Fatalf("FromClientHello error: %v", err)
	}
	const want = "771,49195-49199,0-10-11,29-23,0"
	if ja3 != want {
		t.Errorf("JA3 = %q, want %q", ja3, want)
	}
	expectMD5(t, want, md5hex)
}

// TestFromServerHello checks JA3S = version,cipher,extensions.
func TestFromServerHello(t *testing.T) {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session id len 0
	body = be16(body, 49199)  // chosen cipher
	body = append(body, 0x00) // compression method

	exts := []byte{}
	exts = be16(exts, 0) // server_name, len 0
	exts = be16(exts, 0)
	exts = be16(exts, 43) // supported_versions, len 2
	exts = be16(exts, 2)
	exts = append(exts, 0x03, 0x04)
	body = be16(body, uint16(len(exts)))
	body = append(body, exts...)

	record := tlsRecord(handshakeServerHello, body)

	ja3s, md5hex, err := FromServerHello(record)
	if err != nil {
		t.Fatalf("FromServerHello error: %v", err)
	}
	const want = "771,49199,0-43"
	if ja3s != want {
		t.Errorf("JA3S = %q, want %q", ja3s, want)
	}
	expectMD5(t, want, md5hex)
}

// TestServerName extracts SNI from a ClientHello's server_name extension.
func TestServerName(t *testing.T) {
	host := "cdn.evil.example"
	// server_name extension data: list-len(2) + type(1)=0 + name-len(2) + name.
	name := []byte(host)
	sniData := be16([]byte{}, uint16(len(name)+3)) // server_name_list length
	sniData = append(sniData, 0x00)                // name type = host_name
	sniData = be16(sniData, uint16(len(name)))
	sniData = append(sniData, name...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session id
	body = be16(body, 2)      // ciphers len
	body = be16(body, 49199)
	body = append(body, 0x01, 0x00) // compression
	exts := be16([]byte{}, 0)       // ext type 0 = server_name
	exts = be16(exts, uint16(len(sniData)))
	exts = append(exts, sniData...)
	body = be16(body, uint16(len(exts)))
	body = append(body, exts...)

	record := tlsRecord(handshakeClientHello, body)
	if got := ServerName(record); got != host {
		t.Errorf("ServerName = %q, want %q", got, host)
	}
	// No SNI in a hello without extensions → "".
	if got := ServerName(tlsRecord(handshakeClientHello, func() []byte {
		b := []byte{0x03, 0x03}
		b = append(b, make([]byte, 32)...)
		b = append(b, 0x00)
		b = be16(b, 0) // no ciphers
		b = append(b, 0x01, 0x00)
		return be16(b, 0) // no extensions
	}())); got != "" {
		t.Errorf("ServerName without SNI = %q, want empty", got)
	}
}

// TestGREASEDetection covers the RFC 8701 GREASE set boundaries.
func TestGREASEDetection(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x8a8a, 0xfafa}
	for _, g := range grease {
		if !isGREASE(g) {
			t.Errorf("0x%04x should be GREASE", g)
		}
	}
	notGrease := []uint16{0x0000, 0x1301, 0xc02f, 0x0a0b, 0x0b0a, 771}
	for _, v := range notGrease {
		if isGREASE(v) {
			t.Errorf("0x%04x should NOT be GREASE", v)
		}
	}
}

// TestMalformedRecords ensures untrusted/truncated input errors rather than panics.
func TestMalformedRecords(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{recordTypeHandshake},
		{recordTypeHandshake, 0x03, 0x01, 0x00, 0x50, handshakeClientHello, 0x00, 0x00, 0x49}, // header claims body, none present
		{0x17, 0x03, 0x03, 0x00, 0x01, 0x00},                                                  // application_data, not handshake
	}
	for i, c := range cases {
		if _, _, err := FromClientHello(c); err == nil {
			t.Errorf("case %d: expected error on malformed record", i)
		}
	}
}
