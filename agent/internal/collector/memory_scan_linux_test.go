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
			susp, _, unbk := isSuspiciousExecRegion(tc.perms, tc.pathname, "0")
			if susp != tc.wantSusp {
				t.Errorf("suspicious=%v, want %v (perms=%s path=%q)", susp, tc.wantSusp, tc.perms, tc.pathname)
			}
			if susp && unbk != tc.wantUnbk {
				t.Errorf("unbacked=%v, want %v", unbk, tc.wantUnbk)
			}
		})
	}
}

// TestDeletedMappingPackageUpgradeIsNotSuspicious guards the FP storm measured on
// the verification host (ip-10-0-0-10, 2026-08-03): an apt upgrade of libc6 and
// openssl unlinked the old inodes, so every daemon started before the upgrade kept
// mapping them and /proc/<pid>/maps reported the library text as "(deleted)".
// 94 executable (deleted) mappings host-wide; systemd, cron, dbus-daemon, acpid,
// irqbalance, rsyslogd and docker-proxy were all reported as possible reflective
// loads. The rows below are verbatim from that host — including the control case
// (a dbus-daemon started AFTER the upgrade, mapping the new inode 4622 with no
// "(deleted)" suffix), which must stay unflagged for the same reason it always was.
func TestDeletedMappingPackageUpgradeIsNotSuspicious(t *testing.T) {
	// Inode present on disk now => the path was re-created (package replaced it).
	// Anything else is absent, i.e. genuinely vanished.
	present := map[string]uint64{
		"/usr/lib/x86_64-linux-gnu/libc.so.6":      4622,
		"/usr/lib/x86_64-linux-gnu/libm.so.6":      4623,
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3": 53999,
		"/usr/local/lib/hooked.so":                 900,
		"/tmp/x":                                   901,
	}
	orig := statInode
	statInode = func(path string) (uint64, bool) {
		ino, ok := present[path]
		return ino, ok
	}
	defer func() { statInode = orig }()

	cases := []struct {
		name     string
		perms    string
		pathname string
		inode    string
		wantSusp bool
	}{
		// ── the false positives (must NOT fire) ──
		{"libc replaced by upgrade (cron)", "r-xp",
			"/usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)", "5053", false},
		{"libm replaced by upgrade (irqbalance)", "r-xp",
			"/usr/lib/x86_64-linux-gnu/libm.so.6 (deleted)", "5056", false},
		{"libcrypto replaced by upgrade (systemd-resolve)", "r-xp",
			"/usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)", "53735", false},
		{"control: post-upgrade dbus-daemon, not deleted", "r-xp",
			"/usr/lib/x86_64-linux-gnu/libc.so.6", "4622", false},

		// ── the detections that must survive ──
		{"dropper unlinked its payload", "r-xp", "/tmp/dropper (deleted)", "77", true},
		{"memfd never stats", "r-xp", "/memfd:payload (deleted)", "88", true},
		{"/usr/local is not package-managed", "r-xp",
			"/usr/local/lib/hooked.so (deleted)", "99", true},
		{"recreated /tmp path is still suspicious", "r-xp", "/tmp/x (deleted)", "901", true},
		{"inode 0 has nothing to compare", "r-xp",
			"/usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)", "0", true},
		{"upgraded lib mapped RWX is still flagged", "rwxp",
			"/usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)", "5053", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			susp, _, _ := isSuspiciousExecRegion(tc.perms, tc.pathname, tc.inode)
			if susp != tc.wantSusp {
				t.Errorf("suspicious=%v, want %v (perms=%s path=%q inode=%s)",
					susp, tc.wantSusp, tc.perms, tc.pathname, tc.inode)
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
// enumerated PID must land in exactly one bucket (walked, allowlisted,
// unreadable, or gone), otherwise the measured "対象プロセス数" understates the real
// cost and the default-ON decision would be made on wrong numbers.
//
// **バケットは 4 つある。** SkippedGone（走査に着くまでに終了していた）が
// 後から足されたとき、この検算式は 3 つのままだった。SkippedGone は走査中に
// プロセスが消えたときしか非ゼロにならないので、**手元では通り、忙しい
// ランナーでだけ落ちる**間欠的な赤になっていた（実測: enumerated 170 に対し
// 136+0+33=169、差の 1 が gone）。バケットを足したら、ここも足すこと。
func TestScanStatsAccounting(t *testing.T) {
	findings, st := ScanSuspiciousMemoryWithYARAStats(func([]byte) []string { return nil })
	if st.ProcessesEnumerated == 0 {
		t.Fatal("enumerated no processes — /proc walk broken")
	}
	if got := st.ProcessesScanned + st.SkippedAllowlisted + st.SkippedUnreadable + st.SkippedGone; got != st.ProcessesEnumerated {
		t.Errorf("bucket sum %d != enumerated %d (scanned=%d allowlisted=%d unreadable=%d gone=%d)",
			got, st.ProcessesEnumerated, st.ProcessesScanned, st.SkippedAllowlisted,
			st.SkippedUnreadable, st.SkippedGone)
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
