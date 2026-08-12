package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// tlsSensorStarter is the platform-agnostic handle to the TLS-handshake fingerprint
// sensor. Only Linux provides a real implementation (eBPF kprobe capture of the
// ClientHello/ServerHello → JA3/JA3S); other platforms return nil from the factory. It
// emits tls_handshake findings directly through the event sender.
type tlsSensorStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
