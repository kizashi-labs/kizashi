// Package netparse extracts TLS handshake records from raw IPv4 packets — the
// platform-neutral core shared by packet-capture TLS sensors (e.g. the Windows raw-socket
// JA3 sniffer). Keeping the IPv4/TCP/TLS parsing here (with no OS build tag) makes it
// unit-testable without a live capture, mirroring how the eBPF sensor's decode lives in a
// pure, testable function separate from the kernel plumbing.
package netparse

const (
	ipProtoTCP           = 6
	tlsRecordHandshake   = 0x16
	tlsHandshakeClientHi = 1
)

// TLSPacket is a ClientHello extracted from a captured IPv4/TCP packet.
type TLSPacket struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	Record  []byte // the TLS record bytes (starting at the handshake content type)
}

func ipv4String(b []byte) string {
	// b is 4 bytes. Manual format avoids importing net for a hot path.
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ClientHelloFromIPv4TCP parses a raw IPv4 packet (as a Windows raw socket delivers it,
// IP header included) and returns the embedded TLS ClientHello when the packet is a TCP
// segment whose payload begins with a TLS handshake ClientHello record. ok is false for
// non-IPv4, non-TCP, fragmented, truncated, or non-ClientHello packets. Bounds are checked
// at every step since the bytes come from untrusted capture.
func ClientHelloFromIPv4TCP(pkt []byte) (TLSPacket, bool) {
	if len(pkt) < 20 {
		return TLSPacket{}, false
	}
	// IPv4 only.
	if pkt[0]>>4 != 4 {
		return TLSPacket{}, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return TLSPacket{}, false
	}
	if pkt[9] != ipProtoTCP {
		return TLSPacket{}, false
	}
	// Drop fragments (offset != 0 or MF set) — a ClientHello we care about is not
	// fragmented in practice, and reassembly is out of scope for the fingerprint.
	fragBits := (int(pkt[6])<<8 | int(pkt[7])) & 0x3FFF
	if fragBits != 0 {
		return TLSPacket{}, false
	}
	srcIP := ipv4String(pkt[12:16])
	dstIP := ipv4String(pkt[16:20])

	tcp := pkt[ihl:]
	srcPort := int(tcp[0])<<8 | int(tcp[1])
	dstPort := int(tcp[2])<<8 | int(tcp[3])
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return TLSPacket{}, false
	}
	payload := tcp[dataOff:]
	// TLS record header (5 bytes) + handshake header (≥4): content type, version major 3,
	// and handshake message type = ClientHello.
	if len(payload) < 6 {
		return TLSPacket{}, false
	}
	if payload[0] != tlsRecordHandshake || payload[1] != 0x03 || payload[5] != tlsHandshakeClientHi {
		return TLSPacket{}, false
	}
	return TLSPacket{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Record:  payload,
	}, true
}
