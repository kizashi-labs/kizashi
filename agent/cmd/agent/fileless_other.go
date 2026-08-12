//go:build !(linux && ebpf)

package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// runFilelessService is a no-op unless built with `-tags ebpf` on Linux
// (eBPF fileless-execution sensor — see fileless_linux.go).
func runFilelessService(_ context.Context, _ collector.EventSender, _ string) {}
