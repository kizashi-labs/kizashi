//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/netparse"
)

// tls_sniffer_windows.go — Windows JA3 capture via a raw-socket TLS-handshake sniffer.
//
// The eBPF sensor (Linux) reads the ClientHello from a kprobe and keeps the PID. Windows
// has no equivalent user-mode payload hook: ETW (Schannel/DNS-Client) attributes a PID but
// carries no raw ClientHello bytes, while a raw socket sees the bytes but not the owning
// process. JA3 needs the bytes, so this sensor sniffs TCP with a promiscuous raw socket
// (the same mechanism the DNS collector's fallback uses) and computes the fingerprint;
// process attribution is left empty (the server's C2 blocklist keys on the fingerprint +
// destination, not the PID). Opt-in and best-effort: raw sockets + SIO_RCVALL need admin.
//
// Live verification pending (raw-socket capture cannot run in CI); the IPv4/TCP/TLS parse
// it depends on is unit-tested in agent/internal/netparse.

// sioRCVALL enables promiscuous capture on a raw socket so OUTBOUND ClientHellos are seen
// (WSAIoctl control code; not exported by x/sys/windows).
const sioRCVALL = 0x98000001

// WindowsTLSSensor captures TLS ClientHellos and emits JA3 tls_handshake events.
type WindowsTLSSensor struct {
	socket windows.Handle
	cancel context.CancelFunc
}

// NewWindowsTLSSensor creates the sensor.
func NewWindowsTLSSensor() *WindowsTLSSensor { return &WindowsTLSSensor{} }

// Start opens a promiscuous raw TCP socket and streams JA3 fingerprints until ctx is
// cancelled. Signature matches the ETW remote-thread sensor / tlsSensorStarter.
func (c *WindowsTLSSensor) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	if sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)

	// AF_INET=2, SOCK_RAW=3, IPPROTO_TCP=6.
	sock, err := windows.Socket(2, 3, 6)
	if err != nil {
		return fmt.Errorf("raw TCP socket: %w (管理者権限が必要です)", err)
	}
	c.socket = sock

	// SIO_RCVALL requires the socket be bound to a local interface address first. Best
	// effort: without it we still capture, just not necessarily outbound segments.
	if lip, err := primaryLocalIPv4(); err == nil {
		if err := windows.Bind(sock, &windows.SockaddrInet4{Addr: lip}); err == nil {
			in := uint32(1)
			var ret uint32
			if err := windows.WSAIoctl(sock, sioRCVALL, (*byte)(unsafe.Pointer(&in)), 4, nil, 0, &ret, nil, 0); err != nil {
				slog.Debug("SIO_RCVALL 有効化に失敗（inbound のみ捕捉）", "error", err)
			}
		}
	}

	go c.readPackets(ctx, agentID, sender)
	return nil
}

func (c *WindowsTLSSensor) readPackets(ctx context.Context, agentID string, sender collector.EventSender) {
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
			if ctx.Err() != nil {
				return
			}
			continue
		}
		tp, ok := netparse.ClientHelloFromIPv4TCP(buf[:n])
		if !ok {
			continue
		}
		// No PID from a raw socket; the fingerprint + destination carry the detection.
		batch := collector.ProcessTLSHandshake(agentID, tp.DstIP, tp.DstPort, "", "", 0, tp.Record, nil)
		if batch == nil {
			continue
		}
		if err := sender.SendEvents(ctx, batch); err != nil {
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// Stop cancels the sensor and closes the socket.
func (c *WindowsTLSSensor) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.socket != 0 {
		return windows.Closesocket(c.socket)
	}
	return nil
}

// primaryLocalIPv4 returns the first non-loopback IPv4 address, needed to bind before
// enabling SIO_RCVALL.
func primaryLocalIPv4() ([4]byte, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return [4]byte{}, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			return [4]byte{v4[0], v4[1], v4[2], v4[3]}, nil
		}
	}
	return [4]byte{}, fmt.Errorf("no non-loopback IPv4 address")
}
