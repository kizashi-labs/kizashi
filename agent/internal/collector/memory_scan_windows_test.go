//go:build windows

package collector

import (
	"os"
	"testing"

	syswin "golang.org/x/sys/windows"
)

// TestScanSuspiciousMemoryDetectsRWXWindows allocates committed RWX private
// memory (the canonical process-injection / shellcode indicator) in the test
// process and asserts the VirtualQueryEx scanner flags it. M1-Windows hardware
// check — on a Windows host: `go test ./internal/collector/ -run Memory -v`.
func TestScanSuspiciousMemoryDetectsRWXWindows(t *testing.T) {
	addr, err := syswin.VirtualAlloc(0, 4096,
		syswin.MEM_COMMIT|syswin.MEM_RESERVE, syswin.PAGE_EXECUTE_READWRITE)
	if err != nil || addr == 0 {
		t.Skipf("RWX VirtualAlloc not permitted: %v", err)
	}
	defer syswin.VirtualFree(addr, 0, syswin.MEM_RELEASE)

	self := os.Getpid()
	var hit *MemoryFinding
	for _, f := range ScanSuspiciousMemory() {
		if f.PID == self && f.RWX {
			f := f
			hit = &f
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected an RWX finding for self pid %d, got none", self)
	}
	t.Logf("detected: pid=%d perms=%s unbacked=%v addr=%s reason=%s",
		hit.PID, hit.Perms, hit.Unbacked, hit.Address, hit.Reason)
}

// TestScanProcessMemoryWindows verifies the single-process scan (used for M2
// injection correlation) flags the planted RWX region in the target pid.
func TestScanProcessMemoryWindows(t *testing.T) {
	addr, err := syswin.VirtualAlloc(0, 4096,
		syswin.MEM_COMMIT|syswin.MEM_RESERVE, syswin.PAGE_EXECUTE_READWRITE)
	if err != nil || addr == 0 {
		t.Skipf("RWX VirtualAlloc not permitted: %v", err)
	}
	defer syswin.VirtualFree(addr, 0, syswin.MEM_RELEASE)

	found := false
	for _, f := range ScanProcessMemory(os.Getpid()) {
		if f.RWX || f.Unbacked {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ScanProcessMemory(self) did not flag the planted RWX region")
	}
}
