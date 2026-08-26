// Package ja3 computes JA3 / JA3S TLS-handshake fingerprints from raw TLS records.
//
// JA3 fingerprints the CLIENT: it concatenates the ClientHello's TLS version, the
// offered cipher suites, the extension types, the supported elliptic curves, and the
// EC point formats — decimal values, '-'-joined within a field and ','-joined across
// fields — then MD5s that string. JA3S fingerprints the SERVER's response (version,
// chosen cipher, extension types). Because an implant's TLS stack (Cobalt Strike,
// Metasploit, Sliver, …) produces a stable JA3 regardless of the C2 domain or IP, the
// fingerprint catches process-signature-free malware whose 5-tuple and command line
// reveal nothing — the gap the audit calls "プロセス署名なきC2".
//
// GREASE values (RFC 8701) are randomised padding a client inserts to keep the
// ecosystem tolerant of unknown values; they MUST be excluded or the fingerprint would
// vary run-to-run. This package strips them exactly per the JA3 reference.
//
// The parser is deliberately defensive: every field is length-checked against the
// buffer, and malformed/truncated records return an error rather than panicking, since
// the bytes originate from untrusted network capture.
package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	recordTypeHandshake  = 22
	handshakeClientHello = 1
	handshakeServerHello = 2

	extSupportedGroups = 10 // elliptic curves
	extECPointFormats  = 11
)

var (
	// ErrNotHandshake is returned when the record is not a TLS handshake record.
	ErrNotHandshake = errors.New("ja3: not a TLS handshake record")
	// ErrTruncated is returned when the record ends before a declared field.
	ErrTruncated = errors.New("ja3: truncated record")
	// ErrWrongMessage is returned when the handshake message type is not the one expected.
	ErrWrongMessage = errors.New("ja3: unexpected handshake message type")
)

// isGREASE reports whether v is a GREASE value (RFC 8701): both bytes equal and the low
// nibble is 0xa (0x0a0a, 0x1a1a, …, 0xfafa).
func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// reader is a minimal bounds-checked cursor over a byte slice.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) u8() (byte, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

// u24 reads a 3-byte big-endian length (TLS handshake body length).
func (r *reader) u24() (int, bool) {
	if r.pos+3 > len(r.b) {
		return 0, false
	}
	v := int(r.b[r.pos])<<16 | int(r.b[r.pos+1])<<8 | int(r.b[r.pos+2])
	r.pos += 3
	return v, true
}

// bytes advances n and returns the slice, or false if it would overrun.
func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	s := r.b[r.pos : r.pos+n]
	r.pos += n
	return s, true
}

// handshakeBody validates the TLS record + handshake headers and returns a reader over
// the handshake message body (after the 4-byte handshake header), plus the message type.
func handshakeBody(record []byte) (*reader, byte, error) {
	r := &reader{b: record}
	ct, ok := r.u8()
	if !ok {
		return nil, 0, ErrTruncated
	}
	if ct != recordTypeHandshake {
		return nil, 0, ErrNotHandshake
	}
	if _, ok := r.u16(); !ok { // record version
		return nil, 0, ErrTruncated
	}
	recLen, ok := r.u16()
	if !ok {
		return nil, 0, ErrTruncated
	}
	// Clamp the handshake to the record length (ignore trailing records/padding).
	end := r.pos + int(recLen)
	if end > len(record) {
		end = len(record)
	}
	msgType, ok := r.u8()
	if !ok {
		return nil, 0, ErrTruncated
	}
	bodyLen, ok := r.u24()
	if !ok {
		return nil, 0, ErrTruncated
	}
	bodyEnd := r.pos + bodyLen
	if bodyEnd > end {
		bodyEnd = end
	}
	return &reader{b: record[:bodyEnd], pos: r.pos}, msgType, nil
}

// FromClientHello parses a TLS record carrying a ClientHello and returns the JA3 string
// and its MD5 hex digest.
func FromClientHello(record []byte) (ja3 string, md5hex string, err error) {
	r, msgType, err := handshakeBody(record)
	if err != nil {
		return "", "", err
	}
	if msgType != handshakeClientHello {
		return "", "", ErrWrongMessage
	}

	version, ok := r.u16()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.bytes(32); !ok { // random
		return "", "", ErrTruncated
	}
	sidLen, ok := r.u8()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.bytes(int(sidLen)); !ok {
		return "", "", ErrTruncated
	}

	// Cipher suites.
	csLen, ok := r.u16()
	if !ok {
		return "", "", ErrTruncated
	}
	csRaw, ok := r.bytes(int(csLen))
	if !ok {
		return "", "", ErrTruncated
	}
	ciphers := u16ListNoGREASE(csRaw)

	// Compression methods (skipped in JA3).
	cmLen, ok := r.u8()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.bytes(int(cmLen)); !ok {
		return "", "", ErrTruncated
	}

	exts, curves, pointFormats := parseExtensions(r, true)

	ja3 = strings.Join([]string{
		strconv.Itoa(int(version)),
		joinUint16(ciphers),
		joinUint16(exts),
		joinUint16(curves),
		joinUint16(pointFormats),
	}, ",")
	return ja3, md5Hex(ja3), nil
}

// FromServerHello parses a TLS record carrying a ServerHello and returns the JA3S string
// (version, chosen cipher, extension types) and its MD5 hex digest.
func FromServerHello(record []byte) (ja3s string, md5hex string, err error) {
	r, msgType, err := handshakeBody(record)
	if err != nil {
		return "", "", err
	}
	if msgType != handshakeServerHello {
		return "", "", ErrWrongMessage
	}

	version, ok := r.u16()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.bytes(32); !ok { // random
		return "", "", ErrTruncated
	}
	sidLen, ok := r.u8()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.bytes(int(sidLen)); !ok {
		return "", "", ErrTruncated
	}
	cipher, ok := r.u16()
	if !ok {
		return "", "", ErrTruncated
	}
	if _, ok := r.u8(); !ok { // compression method
		return "", "", ErrTruncated
	}

	exts, _, _ := parseExtensions(r, false)

	ja3s = strings.Join([]string{
		strconv.Itoa(int(version)),
		strconv.Itoa(int(cipher)),
		joinUint16(exts),
	}, ",")
	return ja3s, md5Hex(ja3s), nil
}

// ServerName extracts the SNI host (server_name, extension 0) from a ClientHello record,
// or "" if absent/unparseable. Context for the analyst — a JA3 hit to a named host reads
// far better than a bare IP. Best-effort and never errors on truncation.
func ServerName(record []byte) string {
	r, msgType, err := handshakeBody(record)
	if err != nil || msgType != handshakeClientHello {
		return ""
	}
	if _, ok := r.u16(); !ok { // version
		return ""
	}
	if _, ok := r.bytes(32); !ok { // random
		return ""
	}
	sidLen, ok := r.u8()
	if !ok {
		return ""
	}
	if _, ok := r.bytes(int(sidLen)); !ok {
		return ""
	}
	csLen, ok := r.u16()
	if !ok {
		return ""
	}
	if _, ok := r.bytes(int(csLen)); !ok {
		return ""
	}
	cmLen, ok := r.u8()
	if !ok {
		return ""
	}
	if _, ok := r.bytes(int(cmLen)); !ok {
		return ""
	}
	extTotal, ok := r.u16()
	if !ok {
		return ""
	}
	extEnd := r.pos + int(extTotal)
	if extEnd > len(r.b) {
		extEnd = len(r.b)
	}
	for r.pos < extEnd {
		etype, ok := r.u16()
		if !ok {
			break
		}
		elen, ok := r.u16()
		if !ok {
			break
		}
		data, ok := r.bytes(int(elen))
		if !ok {
			break
		}
		if etype != 0 { // server_name
			continue
		}
		// server_name_list: list-len(2), then entries of type(1)+len(2)+name.
		if len(data) < 5 {
			return ""
		}
		nameType := data[2]
		nameLen := int(data[3])<<8 | int(data[4])
		if nameType != 0 || 5+nameLen > len(data) {
			return ""
		}
		return string(data[5 : 5+nameLen])
	}
	return ""
}

// parseExtensions walks the extension block. It returns the (GREASE-stripped) extension
// type list and, when collectCurves is set (ClientHello only), the supported-groups and
// EC-point-format lists parsed from extensions 10 and 11. A truncated extension block is
// tolerated: whatever parsed cleanly is returned (matches the JA3 reference, which
// fingerprints best-effort rather than rejecting slightly-off captures).
func parseExtensions(r *reader, collectCurves bool) (exts, curves, pointFormats []uint16) {
	extTotal, ok := r.u16()
	if !ok {
		return nil, nil, nil
	}
	extEnd := r.pos + int(extTotal)
	if extEnd > len(r.b) {
		extEnd = len(r.b)
	}
	for r.pos < extEnd {
		etype, ok := r.u16()
		if !ok {
			break
		}
		elen, ok := r.u16()
		if !ok {
			break
		}
		data, ok := r.bytes(int(elen))
		if !ok {
			break
		}
		if isGREASE(etype) {
			continue
		}
		exts = append(exts, etype)
		if !collectCurves {
			continue
		}
		switch etype {
		case extSupportedGroups:
			// uint16 list-length prefix, then the named groups.
			if len(data) >= 2 {
				curves = u16ListNoGREASE(data[2:])
			}
		case extECPointFormats:
			// uint8 list-length prefix, then the formats (bytes).
			if len(data) >= 1 {
				n := int(data[0])
				if n > len(data)-1 {
					n = len(data) - 1
				}
				for _, b := range data[1 : 1+n] {
					pointFormats = append(pointFormats, uint16(b))
				}
			}
		}
	}
	return exts, curves, pointFormats
}

// u16ListNoGREASE decodes a byte slice as consecutive big-endian uint16 values, dropping
// GREASE. A trailing odd byte is ignored.
func u16ListNoGREASE(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+2 <= len(b); i += 2 {
		v := binary.BigEndian.Uint16(b[i:])
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// joinUint16 renders values as decimal strings joined by '-' (empty string for none).
func joinUint16(vs []uint16) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
