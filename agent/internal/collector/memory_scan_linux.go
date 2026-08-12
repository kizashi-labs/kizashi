//go:build linux

// memory_scan_linux.go implements M1 region enumeration on Linux: scan
// /proc/<pid>/maps for RWX (writable+executable) and unbacked-executable regions
// (injection/shellcode indicators). Pure /proc reading, no kernel module.
package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ScanSuspiciousMemoryWithYARA is ScanSuspiciousMemory plus content inspection:
// for each RWX/unbacked executable region it reads the region bytes and runs them
// through scan (a YARA matcher returning matched rule names). An in-memory implant
// (Cobalt Strike beacon, injected shellcode matching a HKTL rule) that never
// touches disk is caught here — complementing the fileless-exec sensor (#390),
// which sees execveat but not code injected into an existing process. A YARA hit
// escalates the finding. scan may be nil (falls back to enumeration only).
func ScanSuspiciousMemoryWithYARA(scan func([]byte) []string) []MemoryFinding {
	out, _ := ScanSuspiciousMemoryWithYARAStats(scan)
	return out
}

// ScanSuspiciousMemoryWithYARAStats is ScanSuspiciousMemoryWithYARA plus the
// per-cycle cost accounting used by the #511 default-ON review and later host
// diagnosis (see MemoryScanStats). Behaviour is identical; only measurement is
// added.
func ScanSuspiciousMemoryWithYARAStats(scan func([]byte) []string) ([]MemoryFinding, MemoryScanStats) {
	start := time.Now()
	raw, st := scanSuspiciousMemoryStats()
	out := make([]MemoryFinding, 0, len(raw))
	for i := range raw {
		f := raw[i]
		// Content-scan genuinely anomalous RWX (writable+executable) regions —
		// the classic injected-shellcode signal — with the CURATED in-memory
		// ruleset. Unbacked read-execute pages are common in ordinary processes,
		// so they are gated by size (shouldEmitMemoryFinding) rather than scanned.
		// Linux has no PAGE_GUARD equivalent in /proc/maps, so guarded is always
		// false here; the shared predicate keeps the OS scanners in step.
		if scan != nil && shouldContentScan(f.RWX, false) {
			if data := readRegion(f.PID, f.Address); len(data) > 0 {
				st.RegionsYARAScanned++
				st.BytesYARAScanned += int64(len(data))
				if names := scan(data); len(names) > 0 {
					f.YARAMatched = true
					f.Reason = "メモリ内YARA一致(" + strings.Join(names, ",") + "): " + f.Reason
				}
			}
		}
		// Drop the benign trampoline/closure/anon-exec classes: a curated YARA
		// hit always reports; otherwise size floors cut the noise (libffi 1-page
		// RWX closures, dlopen/JIT anonymous exec) that flood healthy hosts.
		if shouldEmitMemoryFinding(f) {
			out = append(out, f)
		}
	}
	st.EmittedFindings = len(out)
	st.Duration = time.Since(start)
	return out, st
}

// readRegion reads up to maxRegionScanBytes of the process memory region [start,end)
// from /proc/<pid>/mem. Best-effort: returns nil if unreadable.
func readRegion(pid int, addr string) []byte {
	p := strings.SplitN(addr, "-", 2)
	if len(p) != 2 {
		return nil
	}
	start, err1 := strconv.ParseUint(p[0], 16, 64)
	end, err2 := strconv.ParseUint(p[1], 16, 64)
	if err1 != nil || err2 != nil || end <= start {
		return nil
	}
	size := end - start
	if size > maxRegionScanBytes {
		size = maxRegionScanBytes
	}
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "mem"))
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(start))
	if n == 0 && err != nil {
		return nil
	}
	return buf[:n]
}

// ScanSuspiciousMemory scans every readable process's memory map for RWX or
// unbacked-executable regions, skipping known JIT/runtime processes. Best-effort:
// unreadable PIDs are skipped.
func ScanSuspiciousMemory() []MemoryFinding {
	findings, _ := scanSuspiciousMemoryStats()
	return findings
}

// scanSuspiciousMemoryStats is ScanSuspiciousMemory with the per-cycle
// cost accounting for the #511 load review (see MemoryScanStats).
func scanSuspiciousMemoryStats() ([]MemoryFinding, MemoryScanStats) {
	var st MemoryScanStats
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, st
	}
	var findings []MemoryFinding
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st.ProcessesEnumerated++
		name := readComm(pid)
		if isMemoryScanAllowlisted(name) {
			st.SkippedAllowlisted++
			continue
		}
		procStart := time.Now()
		f, regions, opened := scanPidMapsStats(pid, name)
		if !opened {
			st.SkippedUnreadable++
			continue
		}
		st.observeProcess(pid, name, regions, time.Since(procStart))
		findings = append(findings, f...)
	}
	st.RawFindings = len(findings)
	return findings, st
}

func readComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// isSuspiciousExecRegion classifies a /proc/<pid>/maps line's perms+pathname as
// injection-relevant. A region qualifies when it is RWX (writable+executable —
// classic injected shellcode) OR executable-but-unbacked (no file behind it).
//
// Kernel-provided pseudo-mappings ([vdso], [vsyscall], [vvar]) are executable
// and not file-backed, yet exist in EVERY process — treating them as "unbacked
// executable" produced a systemd/[vdso] false-positive storm on every host
// (r-xp region at 0x7fff…, rwx=false). They are excluded here; only a genuinely
// anonymous or (deleted) executable region counts as unbacked.
func isSuspiciousExecRegion(perms, pathname string) (suspicious, rwx, unbacked bool) {
	if !strings.Contains(perms, "x") {
		return false, false, false // only executable regions are injection-relevant
	}
	rwx = strings.Contains(perms, "w")
	backed := strings.HasPrefix(pathname, "/") && !strings.Contains(pathname, "(deleted)")
	pseudo := strings.HasPrefix(pathname, "[") // [vdso] / [vsyscall] / [vvar] / [stack]
	unbacked = !backed && !pseudo
	return rwx || unbacked, rwx, unbacked
}

// scanPidMapsStats は 1 プロセスの /proc/<pid>/maps を走査し、疑わしい
// 実行可能領域と、走査したリージョン数・maps を開けたかどうかを返す
// (#511 のコスト計上)。opened=false は PID が読めなかったこと —
// 権限不足か、走査中にプロセスが終了したこと — を意味する。
//
// 以前は戻り値を findings だけに絞った scanPidMaps という薄いラッパが
// 併存していたが、呼び出し元が無くなっており staticcheck に U1000 で
// 検出されていたため削除した。
func scanPidMapsStats(pid int, name string) (findings []MemoryFinding, regions int, opened bool) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()

	var out []MemoryFinding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		regions++
		// format: address perms offset dev inode [pathname]
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		pathname := ""
		if len(fields) >= 6 {
			pathname = strings.Join(fields[5:], " ")
		}

		suspicious, rwx, unbacked := isSuspiciousExecRegion(perms, pathname)
		if !suspicious {
			continue
		}
		out = append(out, MemoryFinding{
			PID:         pid,
			ProcessName: name,
			Address:     fields[0],
			Perms:       perms,
			Size:        regionSize(fields[0]),
			Unbacked:    unbacked,
			RWX:         rwx,
			Reason:      classifyRegion(rwx, unbacked),
		})
	}
	// Best-effort: a mid-file read error (e.g. the process exited) just yields a
	// partial map; return what we parsed.
	_ = sc.Err()
	return out, regions, true
}

func regionSize(addr string) uint64 {
	p := strings.SplitN(addr, "-", 2)
	if len(p) != 2 {
		return 0
	}
	start, err1 := strconv.ParseUint(p[0], 16, 64)
	end, err2 := strconv.ParseUint(p[1], 16, 64)
	if err1 != nil || err2 != nil || end < start {
		return 0
	}
	return end - start
}
