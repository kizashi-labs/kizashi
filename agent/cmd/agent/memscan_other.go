//go:build !linux && !windows

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// runMemoryScanService is a no-op on platforms without a memory scanner. Linux
// (/proc/maps) and Windows (VirtualQueryEx) are implemented; macOS
// (mach_vm_region) is a later phase (see the design doc).
func runMemoryScanService(_ context.Context, _ collector.EventSender, _, _ string) {}

// runMemscanBench has nothing to measure where the scanner is unimplemented.
// Used by the -memscan-bench diagnostic (#511).
func runMemscanBench(_ int, _ time.Duration, _, _ bool) {
	fmt.Println("メモリスキャンはこのプラットフォームでは未実装のため、計測できません")
}
