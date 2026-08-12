//go:build linux && !(ebpf && prevention)

package linux

import (
	"context"
	"errors"

	"github.com/edr-platform/agent/internal/collector"
)

// runTLSMonitor is a no-op stub when the "ebpf" build tag is absent. There is no
// non-eBPF fallback for handshake-byte capture (flow-based polling cannot see payload),
// so the TLS fingerprint sensor is simply disabled in non-ebpf builds.
func runTLSMonitor(_ context.Context, _ string, _ collector.EventSender) error {
	return errors.New("eBPF TLS monitor not built (no 'ebpf' tag)")
}
