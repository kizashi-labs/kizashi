//go:build linux && ebpf

package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"

	"github.com/edr-platform/agent/internal/collector"
)

// NetworkMonitor bpf2go bindings are generated from network_monitor.bpf.c (the
// //go:generate directive lives in ebpf_loader.go, `-tags ebpf` — this file requires
// only the "ebpf" tag, not "prevention": it's a plain kprobe/ringbuf monitor with no
// LSM/enforcement hooks, so it belongs in the standard eBPF build, generated
// alongside ProcessMonitor). net_event field offsets (see
// agent/ebpf/network_monitor.bpf.c struct net_event, 96 bytes packed). Kept in sync
// with the C struct.
const (
	neActionOff  = 16 // __u8 action (1=connect)
	neAfOff      = 18 // __u8 af (2=AF_INET, 10=AF_INET6)
	nePIDOff     = 8  // __u32 pid
	neDstIP4Off  = 24 // __u32 dst_ip4 (network byte order)
	neDstIP6Off  = 44 // __u8 dst_ip6[16]
	neDstPortOff = 62 // __u16 dst_port (host order, post bpf_ntohs)
	neCommOff    = 80 // char comm[16]
	neMinLen     = 96

	afINET  = 2
	afINET6 = 10

	actConnect = 1
)

// LoadAndRunEBPFNetworkMonitor loads network_monitor.bpf.c and streams outbound
// TCP connect attempts (kprobe/tcp_connect) as collector.NetworkEvent. Blocks
// until ctx is cancelled; returns early only on a load/attach failure.
func LoadAndRunEBPFNetworkMonitor(ctx context.Context, out chan<- collector.NetworkEvent) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &NetworkMonitorObjects{}
	if err := LoadNetworkMonitorObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF network objects: %w", err)
	}
	defer objs.Close()

	// Attach the outbound-connect kprobe. tcp_connect fires on the SYN — i.e. the
	// connection ATTEMPT — so scans of closed ports are captured (unlike /proc/net
	// polling, which only ever observes ESTABLISHED sockets).
	kp, err := link.Kprobe("tcp_connect", objs.HandleTcpConnect, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe tcp_connect: %w", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		ev, ok := parseNetEvent(record.RawSample)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// parseNetEvent decodes a struct net_event, returning a NetworkEvent for outbound
// TCP connect attempts only (action=connect). ok is false for other actions or
// short records.
func parseNetEvent(raw []byte) (collector.NetworkEvent, bool) {
	if len(raw) < neMinLen {
		return collector.NetworkEvent{}, false
	}
	if raw[neActionOff] != actConnect {
		return collector.NetworkEvent{}, false
	}
	var dstIP string
	switch raw[neAfOff] {
	case afINET:
		dstIP = net.IP(raw[neDstIP4Off : neDstIP4Off+4]).String()
	case afINET6:
		dstIP = net.IP(raw[neDstIP6Off : neDstIP6Off+16]).String()
	default:
		return collector.NetworkEvent{}, false
	}
	pid := binary.NativeEndian.Uint32(raw[nePIDOff : nePIDOff+4])
	dstPort := binary.NativeEndian.Uint16(raw[neDstPortOff : neDstPortOff+2])
	comm := nullTerminated(raw[neCommOff : neCommOff+16])
	// ID and Timestamp are load-bearing, not decoration: ingestion derives the
	// JetStream dedup message-ID from the event ID, falling back to
	// agent+type+timestamp-second+batch-index when it is empty. A port scan emits
	// its connects inside a single second, so ID-less events collapse onto one
	// message-ID and the stream's duplicate window discards all but the first —
	// the scan detector then sees ONE destination port instead of twenty and never
	// reaches its threshold, while the DB still shows every row.
	return collector.NetworkEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		DstIP:       dstIP,
		DstPort:     dstPort,
		Protocol:    "tcp",
		Direction:   "outbound",
		PID:         pid,
		ProcessName: comm,
	}, true
}
