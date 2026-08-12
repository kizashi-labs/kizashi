//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// RawDNSCollector captures DNS queries via an AF_PACKET socket.
//
// Why AF_PACKET, not raw IPPROTO_UDP: AF_INET/SOCK_RAW/IPPROTO_UDP only
// surfaces packets the kernel routes to the local IP stack — i.e. inbound
// UDP. A typical endpoint *generates* DNS queries (it is not a DNS server),
// so the packets we actually need to observe are outbound. AF_PACKET
// captures L2 frames in both directions on every interface, which is what
// outbound query observation requires.
//
// Requires CAP_NET_RAW (agent runs as root).
type RawDNSCollector struct {
	fd int
}

// NewRawDNSCollector creates a new DNS event collector.
func NewRawDNSCollector() *RawDNSCollector {
	return &RawDNSCollector{}
}

// Start opens an AF_PACKET socket and begins capturing DNS queries.
func (c *RawDNSCollector) Start(ctx context.Context, out chan<- collector.DNSEvent) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsU16(uint16(unix.ETH_P_ALL))))
	if err != nil {
		return fmt.Errorf("dns AF_PACKET socket (need CAP_NET_RAW or root): %w", err)
	}
	c.fd = fd

	go c.readPackets(ctx, out)
	return nil
}

func (c *RawDNSCollector) readPackets(ctx context.Context, out chan<- collector.DNSEvent) {
	defer unix.Close(c.fd)

	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set a short read deadline to allow ctx cancellation checks
		tv := unix.Timeval{Sec: 0, Usec: 200000} // 200ms
		_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			// EAGAIN / timeout → check ctx
			continue
		}

		// AF_PACKET delivers a full L2 frame. Skip the 14-byte Ethernet
		// header to reach the IPv4 header that parseDNSPacket expects.
		if n < 14 {
			continue
		}
		ipPkt := buf[14:n]

		// Quick sanity: IPv4 only for now. The IP version is in the
		// upper nibble of the first byte.
		if len(ipPkt) < 1 || ipPkt[0]>>4 != 4 {
			continue
		}

		evt, ok := parseDNSPacket(ipPkt)
		if !ok {
			continue
		}

		select {
		case out <- evt:
		case <-ctx.Done():
			return
		default:
		}
	}
}

// htonsU16 converts a uint16 from host to network byte order. The Linux
// AF_PACKET socket protocol field is a network-order 16-bit ethertype.
func htonsU16(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// Stop closes the raw socket.
func (c *RawDNSCollector) Stop() error {
	if c.fd > 0 {
		return unix.Close(c.fd)
	}
	return nil
}

// ─── Packet parsing ───────────────────────────────────────────

// parseDNSPacket parses a raw IP packet and extracts a DNS query event.
// Returns false if the packet is not a DNS query.
func parseDNSPacket(pkt []byte) (collector.DNSEvent, bool) {
	if len(pkt) < 28 {
		return collector.DNSEvent{}, false
	}

	// IP header: version+IHL in first byte
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return collector.DNSEvent{}, false
	}

	// Must be UDP (protocol = 17)
	if pkt[9] != 17 {
		return collector.DNSEvent{}, false
	}

	// UDP header is 8 bytes: src port (2) | dst port (2) | len (2) | checksum (2)
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 53 {
		return collector.DNSEvent{}, false
	}

	// DNS payload starts at ihl + 8
	dnsStart := ihl + 8
	if len(pkt) < dnsStart+12 {
		return collector.DNSEvent{}, false
	}
	dns := pkt[dnsStart:]

	// DNS header: txid(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
	flags := binary.BigEndian.Uint16(dns[2:4])
	// Bit 15 = QR: 0 = query, 1 = response. We only want outbound queries.
	if flags&0x8000 != 0 {
		return collector.DNSEvent{}, false
	}

	qdcount := binary.BigEndian.Uint16(dns[4:6])
	if qdcount == 0 {
		return collector.DNSEvent{}, false
	}

	domain, qtype, ok := parseDNSQuestion(dns[12:])
	if !ok || domain == "" {
		return collector.DNSEvent{}, false
	}

	return collector.DNSEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Query:     domain,
		QueryType: qtype,
	}, true
}

// parseDNSQuestion parses the first question from the DNS question section.
func parseDNSQuestion(data []byte) (domain, qtype string, ok bool) {
	var labels []string
	offset := 0

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// Pointer compression (0xC0) — not expected in query but guard anyway
		if length&0xC0 == 0xC0 {
			offset += 2
			break
		}
		if offset+1+length > len(data) {
			return "", "", false
		}
		labels = append(labels, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	domain = strings.Join(labels, ".")

	if offset+4 > len(data) {
		return domain, "A", true
	}

	qtypeVal := binary.BigEndian.Uint16(data[offset : offset+2])
	return domain, dnsQTypeString(qtypeVal), true
}

func dnsQTypeString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
