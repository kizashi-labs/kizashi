//go:build !(linux && ebpf && prevention) && !(windows && prevention)

package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// runTamperService is a no-op unless built with `-tags "ebpf prevention"` on
// Linux (eBPF LSM task_kill) or `-tags prevention` on Windows (KizashiPrevention
// ObRegisterCallbacks). Agent self-protection at the kernel level is gated behind
// the prevention build tag so the default build is unaffected.
//
// Note that shipping builds are exactly this no-op: neither tag is set by ci.yml
// or release.yml. The userland self-protection in tamperselfprotect.go is the
// path that actually runs on customer endpoints — it cannot deny a kill, but it
// reports one.
func runTamperService(context.Context, collector.EventSender, string) {}
