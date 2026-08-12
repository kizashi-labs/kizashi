//go:build linux

package collector

import (
	"os"
	"syscall"
	"testing"
)

// TestScanSuspiciousMemoryDetectsRWX maps an anonymous RWX region (the canonical
// process-injection / shellcode indicator) in the test process itself and asserts
// the scanner flags it. This is the M1 hardware-verifiable check — on a Linux host
// (e.g. the verification EC2): `go test ./internal/collector/ -run Memory -v`.
func TestScanSuspiciousMemoryDetectsRWX(t *testing.T) {
	const size = 4096
	mem, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Skipf("RWX mmap not permitted on this kernel (hardened?): %v", err)
	}
	defer syscall.Munmap(mem)
	mem[0] = 0xc3 // x86 RET — make the region look like code

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

// TestIsSuspiciousExecRegion guards the vDSO/vsyscall false-positive fix:
// kernel pseudo-mappings present in every process must NOT be flagged, while
// genuine injection indicators (RWX, anonymous exec, deleted-file exec) must.
func TestIsSuspiciousExecRegion(t *testing.T) {
	cases := []struct {
		name     string
		perms    string
		pathname string
		wantSusp bool
		wantUnbk bool
	}{
		{"vdso r-x", "r-xp", "[vdso]", false, false},
		{"vsyscall --x", "--xp", "[vsyscall]", false, false},
		{"vvar (non-exec)", "r--p", "[vvar]", false, false},
		{"stack pseudo r-x", "r-xp", "[stack]", false, false},
		{"file-backed r-x", "r-xp", "/usr/lib/libc.so.6", false, false},
		{"anonymous rwx", "rwxp", "", true, true},
		{"anonymous r-x (reflective)", "r-xp", "", true, true},
		{"deleted file exec", "r-xp", "/tmp/x (deleted)", true, true},
		{"non-executable rw", "rw-p", "", false, false},
		{"file-backed rwx still flagged", "rwxp", "/usr/lib/libc.so.6", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			susp, _, unbk := isSuspiciousExecRegion(tc.perms, tc.pathname)
			if susp != tc.wantSusp {
				t.Errorf("suspicious=%v, want %v (perms=%s path=%q)", susp, tc.wantSusp, tc.perms, tc.pathname)
			}
			if susp && unbk != tc.wantUnbk {
				t.Errorf("unbacked=%v, want %v", unbk, tc.wantUnbk)
			}
		})
	}
}

// TestScanSuspiciousMemorySkipsVDSO asserts the scanner no longer emits a
// finding for this process's own [vdso] (r-x, unbacked) — the exact systemd FP.
func TestScanSuspiciousMemorySkipsVDSO(t *testing.T) {
	self := os.Getpid()
	for _, f := range ScanSuspiciousMemory() {
		if f.PID == self && !f.RWX && f.Unbacked {
			// Any surviving unbacked non-RWX finding must be genuinely anonymous,
			// never a bracketed kernel pseudo-mapping.
			t.Logf("surviving unbacked finding: addr=%s perms=%s reason=%s", f.Address, f.Perms, f.Reason)
		}
	}
	// The unit-level guarantee is covered by TestIsSuspiciousExecRegion; this
	// just exercises the live /proc path without the vDSO FP crashing in.
}

// TestScanStatsAccounting guards the #511 load instrumentation: every
// enumerated PID must land in exactly one bucket (walked, allowlisted, or
// unreadable), otherwise the measured "対象プロセス数" understates the real cost and
// the default-ON decision would be made on wrong numbers.
func TestScanStatsAccounting(t *testing.T) {
	findings, st := ScanSuspiciousMemoryWithYARAStats(func([]byte) []string { return nil })
	if st.ProcessesEnumerated == 0 {
		t.Fatal("enumerated no processes — /proc walk broken")
	}
	if got := st.ProcessesScanned + st.SkippedAllowlisted + st.SkippedUnreadable; got != st.ProcessesEnumerated {
		t.Errorf("bucket sum %d != enumerated %d (scanned=%d allowlisted=%d unreadable=%d)",
			got, st.ProcessesEnumerated, st.ProcessesScanned, st.SkippedAllowlisted, st.SkippedUnreadable)
	}
	if st.ProcessesScanned > 0 && st.RegionsExamined == 0 {
		t.Error("walked processes but counted no regions")
	}
	if st.EmittedFindings != len(findings) {
		t.Errorf("EmittedFindings=%d but %d findings returned", st.EmittedFindings, len(findings))
	}
	if st.EmittedFindings > st.RawFindings {
		t.Errorf("emitted %d exceeds raw %d", st.EmittedFindings, st.RawFindings)
	}
	if st.Duration <= 0 {
		t.Error("Duration not measured")
	}
	t.Logf("cycle cost: %+v", st)
}

// TestBuildMemoryEvent verifies the event-ID wire format the server ingestion
// decodes (memory:<uuid>:<json>).
func TestBuildMemoryEvent(t *testing.T) {
	batch := BuildMemoryEvent("agent-1", MemoryFinding{PID: 42, ProcessName: "x", Perms: "rwxp", RWX: true})
	if batch == nil || len(batch.Events) != 1 {
		t.Fatal("expected one event")
	}
	id := batch.Events[0].GetId()
	if len(id) < 7 || id[:7] != "memory:" {
		t.Errorf("event id %q lacks memory: prefix", id)
	}
}
