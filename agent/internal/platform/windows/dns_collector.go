//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const (
	// dnsClientGUID is the Microsoft-Windows-DNS-Client ETW provider. Event 3006
	// fires for every DNS query at the Windows resolver (DnsQuery) level, carrying
	// the QueryName/QueryType AND the querying process PID — neither of which the
	// raw-socket sniffer can attribute. It also sees queries the raw UDP/53 sniff
	// misses (the PID-level query record).
	dnsClientGUID = "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"
	etwDNSSession = "EDR-Agent-DNSClient"
	etwDNSQueryID = 3006 // DNS query initiated
)

// WindowsDNSCollector captures DNS queries via real-time ETW when opted in,
// otherwise via a raw socket sniffing UDP/53.
type WindowsDNSCollector struct {
	socket      windows.Handle
	cancel      context.CancelFunc
	out         chan<- collector.DNSEvent
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

// NewWindowsDNSCollector creates a new Windows DNS collector.
func NewWindowsDNSCollector() *WindowsDNSCollector {
	return &WindowsDNSCollector{}
}

// Start begins capturing DNS queries. Real-time ETW (Microsoft-Windows-DNS-Client)
// attributes each query to its process (PID) and is OPT-IN via EDR_AGENT_ETW (the
// same flag as the process/network collectors). The raw-socket sniffer remains
// the default and the automatic fallback on any failure.
func (c *WindowsDNSCollector) Start(ctx context.Context, out chan<- collector.DNSEvent) error {
	if etwEnabled() {
		if err := c.startETW(ctx, out); err != nil {
			slog.Warn("ETW DNS監視を開始できませんでした。rawソケットにフォールバックします", "error", err)
		} else {
			slog.Info("ETW DNS監視を開始しました (Microsoft-Windows-DNS-Client)")
			return nil
		}
	}

	// AF_INET=2, SOCK_RAW=3, IPPROTO_UDP=17
	sock, err := windows.Socket(2, 3, 17)
	if err != nil {
		// Raw sockets may require elevated privileges
		return fmt.Errorf("raw socket: %w (管理者権限が必要です)", err)
	}
	c.socket = sock

	go c.readPackets(ctx, out)
	return nil
}

// startETW opens a real-time ETW session on the DNS-Client provider and streams
// DNS query events. Any failure is returned so the caller can fall back.
func (c *WindowsDNSCollector) startETW(ctx context.Context, out chan<- collector.DNSEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.out = out
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, etwDNSSession, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *WindowsDNSCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(dnsClientGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve dns-client provider: %w", err)
	}
	prov.EnableLevel = 0xFF // TRACE_LEVEL_VERBOSE

	session := etw.NewRealTimeSession(etwDNSSession)
	if err := session.EnableProvider(prov); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("enable provider: %w", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(session)
	consumer.EventCallback = func(e *etw.Event) error {
		c.handleETWEvent(e, c.out)
		return nil
	}
	if err := consumer.Start(); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("start consumer: %w", err)
	}

	c.etwSession = session
	c.etwConsumer = consumer
	return consumer, nil
}

func (c *WindowsDNSCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent converts a DNS-Client query event into a DNSEvent, attributing
// it to the querying process. It stays lightweight so the ETW callback never
// blocks the trace.
func (c *WindowsDNSCollector) handleETWEvent(e *etw.Event, out chan<- collector.DNSEvent) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETW DNSイベント処理でパニックを回復しました", "panic", r)
		}
	}()

	if e.System.EventID != etwDNSQueryID {
		return
	}
	name, _ := e.GetPropertyString("QueryName")
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return
	}

	qtype := "A"
	if qt, ok := e.GetPropertyString("QueryType"); ok && qt != "" {
		if n, err := strconv.ParseUint(qt, 0, 16); err == nil {
			qtype = windowsDNSQTypeString(uint16(n))
		} else {
			qtype = qt
		}
	}

	evt := collector.DNSEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Query:     name,
		QueryType: qtype,
		PID:       e.System.Execution.ProcessID,
	}
	select {
	case out <- evt:
	default:
	}
}

func (c *WindowsDNSCollector) readPackets(ctx context.Context, out chan<- collector.DNSEvent) {
	defer windows.Closesocket(c.socket)

	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := windows.Recvfrom(c.socket, buf, 0)
		if err != nil {
			continue
		}

		evt, ok := parseWindowsDNSPacket(buf[:n])
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

// Stop cancels the collector's context — the ETW supervisor observes this to tear
// down its session/consumer — and closes the raw socket if the sniffer is active.
func (c *WindowsDNSCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.socket != 0 {
		return windows.Closesocket(c.socket)
	}
	return nil
}

// parseWindowsDNSPacket parses a raw IP packet (Windows raw socket includes IP header).
func parseWindowsDNSPacket(pkt []byte) (collector.DNSEvent, bool) {
	if len(pkt) < 28 {
		return collector.DNSEvent{}, false
	}

	// IP header
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return collector.DNSEvent{}, false
	}

	// Must be UDP
	if pkt[9] != 17 {
		return collector.DNSEvent{}, false
	}

	// UDP: dst port
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 53 {
		return collector.DNSEvent{}, false
	}

	dnsStart := ihl + 8
	if len(pkt) < dnsStart+12 {
		return collector.DNSEvent{}, false
	}
	dns := pkt[dnsStart:]

	// QR bit: 0 = query
	flags := binary.BigEndian.Uint16(dns[2:4])
	if flags&0x8000 != 0 {
		return collector.DNSEvent{}, false
	}

	qdcount := binary.BigEndian.Uint16(dns[4:6])
	if qdcount == 0 {
		return collector.DNSEvent{}, false
	}

	domain, qtype, ok := parseWindowsDNSQuestion(dns[12:])
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

func parseWindowsDNSQuestion(data []byte) (domain, qtype string, ok bool) {
	var labels []string
	offset := 0

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
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
	return domain, windowsDNSQTypeString(qtypeVal), true
}

func windowsDNSQTypeString(t uint16) string {
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
