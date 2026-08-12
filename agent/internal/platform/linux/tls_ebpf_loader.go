//go:build linux && ebpf && prevention

package linux

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/edr-platform/agent/internal/collector"
)

// TLSMonitor bpf2go bindings (TLSMonitorObjects / LoadTLSMonitorObjects) are generated
// from agent/ebpf/tls_monitor.bpf.c by CI (agent-ebpf.yml), same as the network monitor.
// The tls_event decode lives in parseTLSEvent (tls_ebpf_parse.go), kept in sync with the
// C struct offsets and unit-tested there without the eBPF toolchain.

// LoadAndRunTLSMonitor loads tls_monitor.bpf.c, attaches the tcp_sendmsg/tcp_recvmsg
// kprobes, and streams JA3/JA3S fingerprints as tls_handshake events until ctx is
// cancelled. Returns early only on a load/attach failure.
func LoadAndRunTLSMonitor(ctx context.Context, agentID string, sender collector.EventSender) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &TLSMonitorObjects{}
	if err := LoadTLSMonitorObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF TLS objects: %w", err)
	}
	defer objs.Close()

	sp, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe tcp_sendmsg: %w", err)
	}
	defer sp.Close()

	rp, err := link.Kprobe("tcp_recvmsg", objs.HandleTcpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe tcp_recvmsg: %w", err)
	}
	defer rp.Close()

	rd, err := ringbuf.NewReader(objs.TlsEvents)
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
		cap, ok := parseTLSEvent(record.RawSample)
		if !ok {
			continue
		}
		batch := buildTLSEvent(agentID, cap)
		if batch == nil {
			continue // no fingerprint (truncated/malformed handshake)
		}
		if err := sender.SendEvents(ctx, batch); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Transient send failure — drop this fingerprint and keep streaming.
			continue
		}
	}
}
