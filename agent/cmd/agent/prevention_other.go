//go:build !(linux && ebpf && prevention) && !(windows && prevention) && !(darwin && esf && prevention && cgo)

package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// runPreventionService is a no-op unless built with the prevention tag on a
// supported platform: `-tags "ebpf prevention"` on Linux (eBPF LSM),
// `-tags prevention` on Windows (KizashiPrevention driver), or
// `-tags "esf prevention"` on macOS (ESF AUTH_EXEC). All are gated behind the
// prevention build tag so the default build is unaffected. On every other
// platform/tag the agent runs in observe mode without in-kernel prevention.
func runPreventionService(_ context.Context, _ collector.EventSender, _, _ string) {}
