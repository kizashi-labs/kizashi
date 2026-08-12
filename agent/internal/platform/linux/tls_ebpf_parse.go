//go:build linux

package linux

import (
	"encoding/binary"
	"net"

	v1 "github.com/edr-platform/proto/agent/v1"

	"github.com/edr-platform/agent/internal/collector"
)

// tls_event field offsets — MUST match struct tls_event in agent/ebpf/tls_monitor.bpf.c
// (380 bytes). Same offset-decode discipline as parseNetEvent.
const (
	teAFOff      = 16 // __u8 af
	teDirOff     = 17 // __u8 direction (1=client, 2=server)
	teDstPortOff = 18 // __u16 dst_port (host order)
	teDstIP4Off  = 20 // __u32 dst_ip4 (network byte order)
	teDstIP6Off  = 24 // __u8 dst_ip6[16]
	tePIDOff     = 8  // __u32 pid
	teDataLenOff = 40 // __u16 data_len
	teCommOff    = 44 // char comm[16]
	teDataOff    = 60 // __u8 data[320]
	teCapLen     = 320
	teMinLen     = teDataOff // header must be fully present

	tlsDirClient = 1
	tlsDirServer = 2

	// AF_INET / AF_INET6 — defined locally (not from the ebpf-tagged loader) so the
	// pure parser and its unit test build without the "ebpf" tag.
	tlsAFInet  = 2
	tlsAFInet6 = 10
)

// tlsNullTerminated trims a fixed-width C string at its first NUL. A local copy so this
// file needs no symbol from the ebpf-tagged loaders.
func tlsNullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// tlsCapture is a decoded TLS-handshake capture from the eBPF ring buffer.
type tlsCapture struct {
	DstIP     string
	DstPort   uint16
	PID       uint32
	Comm      string
	Direction uint8  // tlsDirClient / tlsDirServer
	Data      []byte // the captured ClientHello/ServerHello bytes (len = data_len)
}

// parseTLSEvent decodes a struct tls_event. ok is false for short records, an
// unknown address family, an unknown direction, or an empty/oversized data_len.
func parseTLSEvent(raw []byte) (tlsCapture, bool) {
	if len(raw) < teMinLen {
		return tlsCapture{}, false
	}
	dir := raw[teDirOff]
	if dir != tlsDirClient && dir != tlsDirServer {
		return tlsCapture{}, false
	}
	var dstIP string
	switch raw[teAFOff] {
	case tlsAFInet:
		dstIP = net.IP(raw[teDstIP4Off : teDstIP4Off+4]).String()
	case tlsAFInet6:
		dstIP = net.IP(raw[teDstIP6Off : teDstIP6Off+16]).String()
	default:
		return tlsCapture{}, false
	}
	dataLen := int(binary.NativeEndian.Uint16(raw[teDataLenOff : teDataLenOff+2]))
	if dataLen <= 0 || dataLen > teCapLen {
		return tlsCapture{}, false
	}
	if len(raw) < teDataOff+dataLen {
		return tlsCapture{}, false
	}
	data := make([]byte, dataLen)
	copy(data, raw[teDataOff:teDataOff+dataLen])

	return tlsCapture{
		DstIP:     dstIP,
		DstPort:   binary.NativeEndian.Uint16(raw[teDstPortOff : teDstPortOff+2]),
		PID:       binary.NativeEndian.Uint32(raw[tePIDOff : tePIDOff+4]),
		Comm:      tlsNullTerminated(raw[teCommOff : teCommOff+16]),
		Direction: dir,
		Data:      data,
	}, true
}

// buildTLSEvent turns a decoded capture into an emittable tls_handshake EventBatch:
// a ClientHello capture is fingerprinted as JA3, a ServerHello as JA3S. Returns nil
// when the capture yields no fingerprint (collector.ProcessTLSHandshake handles that).
func buildTLSEvent(agentID string, cap tlsCapture) *v1.EventBatch {
	var clientHello, serverHello []byte
	switch cap.Direction {
	case tlsDirClient:
		clientHello = cap.Data
	case tlsDirServer:
		serverHello = cap.Data
	}
	return collector.ProcessTLSHandshake(agentID, cap.DstIP, int(cap.DstPort), "", cap.Comm, int(cap.PID), clientHello, serverHello)
}
