package collector

import "testing"

func TestIsMemoryScanAllowlisted(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"node", true},
		{"chrome", true},
		{"next-server", true},
		// Linux /proc/comm truncates "next-server (v15.1.0)" to "next-server (v";
		// the space-split base must still match the allowlist.
		{"next-server (v", true},
		{"next-server (v15.1.0)", true},
		{"node.exe", true},
		{"systemd", false},
		{"packagekitd", false},
		{"evil-injector", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isMemoryScanAllowlisted(tc.name); got != tc.want {
			t.Errorf("isMemoryScanAllowlisted(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestShouldEmitMemoryFinding(t *testing.T) {
	page := uint64(4 << 10) // 4 KiB
	cases := []struct {
		name string
		f    MemoryFinding
		want bool
	}{
		// YARA content match always reports, regardless of size/class.
		{"yara match tiny rwx", MemoryFinding{RWX: true, Size: page, YARAMatched: true}, true},
		{"yara match tiny unbacked", MemoryFinding{Unbacked: true, Size: page, YARAMatched: true}, true},
		// RWX: single-page libffi/JIT closure dropped; larger reported.
		{"rwx 1 page (libffi)", MemoryFinding{RWX: true, Size: page}, false},
		{"rwx 8 KiB", MemoryFinding{RWX: true, Size: 8 << 10}, true},
		{"rwx 256 KiB (injected)", MemoryFinding{RWX: true, Size: 256 << 10}, true},
		// Unbacked read-execute: noisy class, only large anonymous payloads report.
		{"unbacked 84 KiB (packagekitd)", MemoryFinding{Unbacked: true, Size: 84 << 10}, false},
		{"unbacked 256 KiB (reflective payload)", MemoryFinding{Unbacked: true, Size: 256 << 10}, true},
		{"unbacked 1 page (trampoline)", MemoryFinding{Unbacked: true, Size: page}, false},
	}
	for _, tc := range cases {
		if got := shouldEmitMemoryFinding(tc.f); got != tc.want {
			t.Errorf("%s: shouldEmitMemoryFinding = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestShouldContentScan locks the content-scan gate shared by every OS scanner.
// Two properties matter and are easy to regress:
//   - only RWX regions are read, so enabling in-memory YARA does not multiply the
//     scan cost across the far more numerous unbacked read-execute regions;
//   - guard pages are never read. The guard exists so the owning process is
//     notified on access (stack growth relies on it), so reading one is not a
//     neutral observation — enumeration still reports the region.
func TestShouldContentScan(t *testing.T) {
	cases := []struct {
		name    string
		rwx     bool
		guarded bool
		want    bool
	}{
		{"rwx region is scanned", true, false, true},
		{"guarded rwx region is skipped", true, true, false},
		{"non-rwx region is skipped", false, false, false},
		{"guarded non-rwx region is skipped", false, true, false},
	}
	for _, c := range cases {
		if got := shouldContentScan(c.rwx, c.guarded); got != c.want {
			t.Errorf("%s: shouldContentScan(rwx=%v, guarded=%v)=%v, want %v",
				c.name, c.rwx, c.guarded, got, c.want)
		}
	}
}

// TestMaxRegionScanBytesBounded guards the per-region read cap: it bounds how
// much memory one suspicious region can pull into the agent, so a process with a
// multi-gigabyte RWX heap cannot stall a scan cycle.
func TestMaxRegionScanBytesBounded(t *testing.T) {
	if maxRegionScanBytes <= 0 {
		t.Fatal("read cap must be positive")
	}
	if maxRegionScanBytes > 16<<20 {
		t.Errorf("read cap %d exceeds 16MiB — a scan cycle walks every process, so "+
			"a large cap multiplies across regions", maxRegionScanBytes)
	}
}
