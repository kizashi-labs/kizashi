//go:build windows

package main

import winplat "github.com/edr-platform/agent/internal/platform/windows"

// benchEnableSeDebug enables SeDebugPrivilege for the memory-scan bench so it
// walks the same processes the production agent can. Without it the bench skips
// system processes on a cheap failed OpenProcess and understates the real cost.
// Used by the -memscan-bench diagnostic (#511).
func benchEnableSeDebug() bool {
	winplat.EnableSeDebugPrivilege() // best-effort; logs on failure
	return true
}
