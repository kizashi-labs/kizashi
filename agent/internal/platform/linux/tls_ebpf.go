//go:build linux

package linux

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// TLSHandshakeSensor captures TLS ClientHello/ServerHello bytes via eBPF
// (kprobe/tcp_sendmsg + kprobe/tcp_recvmsg), computes JA3/JA3S fingerprints, and
// emits tls_handshake events for the server's C2 blocklist matcher. It requires the
// "ebpf" build tag and a kernel that permits reading socket-payload user memory from a
// kprobe (>= 5.8, as with the flow monitor); without the tag it is a no-op, since there
// is no payload-capture fallback (flow-based /proc polling cannot see handshake bytes).
type TLSHandshakeSensor struct {
	cancel context.CancelFunc
}

// NewTLSHandshakeSensor creates a TLS-handshake fingerprint sensor.
func NewTLSHandshakeSensor() *TLSHandshakeSensor {
	return &TLSHandshakeSensor{}
}

// Start loads the eBPF program and streams fingerprints until ctx is cancelled. It is
// invoked from a goroutine by the agent, so blocking here is expected. Returns the
// load/attach error (nil when the "ebpf" tag is absent → silently disabled) so the
// caller can decide whether to log it. Signature mirrors the ETW remote-thread sensor.
func (s *TLSHandshakeSensor) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	if sender == nil {
		return nil
	}
	ctx, s.cancel = context.WithCancel(ctx)
	return runTLSMonitor(ctx, agentID, sender)
}

// Stop cancels the sensor.
func (s *TLSHandshakeSensor) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}
