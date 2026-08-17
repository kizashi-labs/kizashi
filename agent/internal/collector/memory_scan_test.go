package collector

import (
	"strings"
	"testing"
)

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

func TestShannonEntropy(t *testing.T) {
	// 512 KiB of a single repeated byte: one symbol, zero bits of surprise.
	zeros := make([]byte, 512<<10)
	if h := shannonEntropy(zeros); h != 0 {
		t.Errorf("shannonEntropy(all-zero) = %v, want 0", h)
	}

	// Every byte value equally often is the 8.0 ceiling by construction.
	uniform := make([]byte, 256*64)
	for i := range uniform {
		uniform[i] = byte(i % 256)
	}
	if h := shannonEntropy(uniform); h != 8 {
		t.Errorf("shannonEntropy(uniform) = %v, want exactly 8", h)
	}

	// Two symbols in equal proportion is exactly 1 bit/byte — this pins the
	// units. A version that summed natural logs would return 0.693 here and
	// still pass both cases above.
	half := make([]byte, 4096)
	for i := range half {
		half[i] = byte(i % 2)
	}
	if h := shannonEntropy(half); h != 1 {
		t.Errorf("shannonEntropy(two symbols, equal) = %v, want exactly 1", h)
	}

	if h := shannonEntropy(nil); h != 0 {
		t.Errorf("shannonEntropy(nil) = %v, want 0", h)
	}
}

func TestAnnotateEntropy(t *testing.T) {
	// Unreadable region: Entropy stays 0 and the reason is untouched. This is
	// the case that must not read as "low entropy" anywhere downstream.
	f := MemoryFinding{Reason: "RWX private実行領域（インジェクションの可能性）"}
	before := f.Reason
	annotateEntropy(&f, nil)
	if f.Entropy != 0 || f.Reason != before {
		t.Errorf("empty data: got entropy=%v reason=%q, want 0 and unchanged", f.Entropy, f.Reason)
	}

	// Packed/encrypted shape: measured, and the reason says so.
	packed := make([]byte, 128<<10)
	for i := range packed {
		packed[i] = byte(i % 256)
	}
	f = MemoryFinding{Reason: "RWX private実行領域（インジェクションの可能性）"}
	annotateEntropy(&f, packed)
	if f.Entropy < highEntropyThreshold {
		t.Errorf("packed data: entropy = %v, want >= %v", f.Entropy, highEntropyThreshold)
	}
	if f.Reason == before {
		t.Error("packed data: reason was not annotated")
	}
	if !strings.Contains(f.Reason, before) {
		t.Errorf("packed data: reason %q dropped the original classification", f.Reason)
	}

	// Low-entropy shape: measured, but the reason must stay clean — otherwise
	// every content-scanned region carries the corroboration text and the text
	// stops meaning anything.
	sparse := make([]byte, 128<<10)
	f = MemoryFinding{Reason: before}
	annotateEntropy(&f, sparse)
	if f.Entropy != 0 {
		t.Errorf("sparse data: entropy = %v, want 0", f.Entropy)
	}
	if f.Reason != before {
		t.Errorf("sparse data: reason = %q, want unchanged", f.Reason)
	}
}

// Entropy annotates; it must never promote. A region the size floors drop stays
// dropped however high its entropy is — a 4 KiB RWX page full of packed-looking
// bytes is also what a JIT constant pool looks like.
func TestEntropyDoesNotBypassSizeFloor(t *testing.T) {
	f := MemoryFinding{RWX: true, Size: 4096}
	packed := make([]byte, 64<<10)
	for i := range packed {
		packed[i] = byte(i % 256)
	}
	annotateEntropy(&f, packed)
	if f.Entropy < highEntropyThreshold {
		t.Fatalf("test setup: entropy = %v, want high", f.Entropy)
	}
	if shouldEmitMemoryFinding(f) {
		t.Error("high entropy promoted a finding below the size floor")
	}
}
