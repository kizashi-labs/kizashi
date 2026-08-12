//go:build linux && !ebpf

package linux

import (
	"context"
	"fmt"

	"github.com/edr-platform/agent/internal/collector"
)

// runEBPFProcessMonitor is a stub used when the "ebpf" build tag is not set.
// It always returns an error so the caller falls back to pollProcFS.
func runEBPFProcessMonitor(_ context.Context, _ chan<- collector.ProcessEvent) error {
	return fmt.Errorf("eBPF support not compiled in (rebuild with -tags ebpf)")
}
