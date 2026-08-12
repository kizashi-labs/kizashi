//go:build !(windows && prevention) && !(linux && ebpf && prevention)

package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// runCredService is a no-op unless built with `-tags prevention` on Windows
// (KizashiPrevention driver M3 LSASS credential-access detection) or
// `-tags "ebpf prevention"` on Linux (eBPF LSM ptrace_access_check — see
// cred_linux.go).
func runCredService(_ context.Context, _ collector.EventSender, _ string) {}
