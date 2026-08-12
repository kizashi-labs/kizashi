//go:build !(linux && ebpf && prevention)

package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// runHostIntegrityService is a no-op unless built with `-tags "ebpf prevention"`
// on Linux (eBPF kernel-module/namespace/capability sensor — see
// hostintegrity_linux.go).
func runHostIntegrityService(_ context.Context, _ collector.EventSender, _ string) {}
