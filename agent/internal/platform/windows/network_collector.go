//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const (
	// kernelNetworkGUID is the Microsoft-Windows-Kernel-Network ETW provider.
	// It emits a real-time event for every TCP connect/accept (and more), which
	// closes the gap left by the 500ms TCP-table polling — short-lived
	// connections (e.g. sub-second C2 beacons) are no longer missed.
	kernelNetworkGUID = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
	etwNetSessionName = "EDR-Agent-KernelNetwork"
	etwTCPConnectV4ID = 12 // KERNEL_NETWORK_TASK_TCP connect, IPv4 (outbound)
	etwTCPConnectV6ID = 28 // connect, IPv6
	etwTCPAcceptV4ID  = 17 // accept, IPv4 (inbound)
	etwTCPAcceptV6ID  = 31 // accept, IPv6
)

// Windows IP Helper API constants
//
// **UDP は列挙していません。** GetExtendedUdpTable の proc と
// udpTableOwnerPID の定数は宣言だけされていて、呼び出す側が一度も書かれて
// いませんでした（staticcheck U1000）。実装が別へ移ったのではなく、
// 作られなかったものです。宣言だけ残すと「対応済み」に見えるので外します。
//
// Linux 側は /proc/net/udp と /proc/net/udp6 を読んでいるため、network イベントの
// UDP 被覆は **OS で非対称**です。追跡は docs/debt/P4.md の P4-13。
var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDConnections = 4
	afInet                      = 2
)

// MIB_TCPROW_OWNER_PID matches the Windows structure
type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// tcpTableOwnerPIDStruct wraps a slice of tcpRowOwnerPID
type tcpTableOwnerPIDStruct struct {
	NumEntries uint32
	Table      [1]tcpRowOwnerPID
}

// WindowsNetworkCollector observes TCP connections, via real-time ETW when
// opted in, otherwise by polling the IP Helper API TCP table.
type WindowsNetworkCollector struct {
	cancel      context.CancelFunc
	out         chan<- collector.NetworkEvent
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

// NewWindowsNetworkCollector creates a new Windows network collector.
func NewWindowsNetworkCollector() *WindowsNetworkCollector {
	return &WindowsNetworkCollector{}
}

// Start begins observing network connections. Real-time ETW
// (Microsoft-Windows-Kernel-Network) captures every TCP connect/accept with no
// polling gaps, but requires Administrator and is OPT-IN via EDR_AGENT_ETW (the
// same flag as the process collector). The proven TCP-table polling remains the
// default and the automatic fallback on any failure.
func (c *WindowsNetworkCollector) Start(ctx context.Context, out chan<- collector.NetworkEvent) error {
	if etwEnabled() {
		if err := c.startETW(ctx, out); err != nil {
			slog.Warn("ETWネットワーク監視を開始できませんでした。ポーリングにフォールバックします", "error", err)
		} else {
			slog.Info("ETWネットワーク監視を開始しました (Microsoft-Windows-Kernel-Network)")
			return nil
		}
	}
	go c.poll(ctx, out)
	return nil
}

// startETW opens a real-time ETW session on the Kernel-Network provider and
// streams TCP connect/accept events. Any failure is returned so the caller can
// fall back to polling.
func (c *WindowsNetworkCollector) startETW(ctx context.Context, out chan<- collector.NetworkEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.out = out
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, etwNetSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *WindowsNetworkCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(kernelNetworkGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel-network provider: %w", err)
	}
	prov.EnableLevel = 0xFF // TRACE_LEVEL_VERBOSE

	session := etw.NewRealTimeSession(etwNetSessionName)
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

func (c *WindowsNetworkCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent converts a Kernel-Network TCP connect/accept event into a
// NetworkEvent. It stays lightweight (no OpenProcess / name resolution) so the
// ETW trace callback never blocks and drops buffers; PID is carried and process
// name resolution is left to consumers.
func (c *WindowsNetworkCollector) handleETWEvent(e *etw.Event, out chan<- collector.NetworkEvent) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWネットワークイベント処理でパニックを回復しました", "panic", r)
		}
	}()

	var direction string
	switch e.System.EventID {
	case etwTCPConnectV4ID, etwTCPConnectV6ID:
		direction = "outbound"
	case etwTCPAcceptV4ID, etwTCPAcceptV6ID:
		direction = "inbound"
	default:
		return
	}

	// Manifest fields: saddr/sport = source (initiator), daddr/dport = destination.
	dstIP, _ := e.GetPropertyString("daddr")
	if dstIP == "" {
		return
	}
	if dstIP == "127.0.0.1" || dstIP == "::1" {
		return
	}
	srcIP, _ := e.GetPropertyString("saddr")

	evt := collector.NetworkEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		SrcPort:   etwPort(e, "sport"),
		DstIP:     dstIP,
		DstPort:   etwPort(e, "dport"),
		Protocol:  "tcp",
		Direction: direction,
		PID:       etwPID(e, "PID"),
	}
	select {
	case out <- evt:
	default:
	}
}

// etwPort parses a uint16 port from an ETW event property.
func etwPort(e *etw.Event, key string) uint16 {
	if s, ok := e.GetPropertyString(key); ok {
		if n, err := strconv.ParseUint(s, 0, 16); err == nil {
			return uint16(n)
		}
	}
	return 0
}

// etwPID parses a uint32 PID from an ETW event property.
func etwPID(e *etw.Event, key string) uint32 {
	if s, ok := e.GetPropertyString(key); ok {
		if n, err := strconv.ParseUint(s, 0, 32); err == nil {
			return uint32(n)
		}
	}
	return 0
}

func (c *WindowsNetworkCollector) poll(ctx context.Context, out chan<- collector.NetworkEvent) {
	known := make(map[string]bool)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conns := c.getTCPConnections()
			current := make(map[string]bool)

			for _, conn := range conns {
				key := fmt.Sprintf("%s:%d->%s:%d", conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
				current[key] = true

				if !known[key] {
					select {
					case out <- conn:
					case <-ctx.Done():
						return
					default:
					}
				}
			}
			known = current
		}
	}
}

// getTCPConnections uses GetExtendedTcpTable to enumerate TCP connections.
func (c *WindowsNetworkCollector) getTCPConnections() []collector.NetworkEvent {
	var size uint32 = 0
	// First call to get required buffer size
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPIDConnections,
		0,
	)

	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPIDConnections,
		0,
	)
	if ret != 0 {
		return nil
	}

	table := (*tcpTableOwnerPIDStruct)(unsafe.Pointer(&buf[0]))
	numEntries := int(table.NumEntries)

	rowSize := unsafe.Sizeof(tcpRowOwnerPID{})
	var events []collector.NetworkEvent

	for i := 0; i < numEntries; i++ {
		row := (*tcpRowOwnerPID)(unsafe.Add(unsafe.Pointer(&table.Table[0]), uintptr(i)*rowSize))

		// Only ESTABLISHED connections (state = 5)
		if row.State != 5 {
			continue
		}

		srcIP := int32ToIP(row.LocalAddr)
		dstIP := int32ToIP(row.RemoteAddr)

		// Skip loopback
		if srcIP == "127.0.0.1" || dstIP == "127.0.0.1" {
			continue
		}
		// Skip unconnected
		if dstIP == "0.0.0.0" {
			continue
		}

		srcPort := uint16(ntohs(uint16(row.LocalPort)))
		dstPort := uint16(ntohs(uint16(row.RemotePort)))

		evt := collector.NetworkEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  "tcp",
			Direction: "outbound",
			PID:       row.OwningPID,
		}

		// Try to resolve process name from PID
		evt.ProcessName = pidToName(row.OwningPID)

		events = append(events, evt)
	}

	return events
}

// Stop cancels the collector's context, which the ETW supervisor observes to tear
// down its session/consumer; polling mode also stops via the cancelled context.
func (c *WindowsNetworkCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────

func int32ToIP(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b).String()
}

func ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return binary.LittleEndian.Uint16(b)
}

func pidToName(pid uint32) string {
	if pid == 0 {
		return "System Idle Process"
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}
