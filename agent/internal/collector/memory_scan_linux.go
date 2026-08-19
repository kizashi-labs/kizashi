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
	"syscall"
	"time"
)

// statInode returns the inode currently backing path. Overridable in tests so the
// package-upgrade discriminator can be exercised without unlinking real libraries.
var statInode = func(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

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
				// Same bytes, second question: YARA asks "is this a *known*
				// implant", entropy asks "is this packed at all". A fresh
				// payload matches no curated rule but still reads as ciphertext.
				annotateEntropy(&f, data)
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
	// **走査できなかったことを、端末の外に出します。** これまでこの数値は
	// slog.Debug の1行だけで、既定の水準では出ませんでした。
	st.report()
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
		f, regions, skip := scanPidMapsStatsFn(pid, name)
		switch skip {
		case skipDenied:
			// **開こうとして断られました。** この中は見ていません。
			st.SkippedUnreadable++
			continue
		case skipGone:
			// 走査するまでに終了していました。**正常です。**
			st.SkippedGone++
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

// packageManagedPrefixes are the directories a distribution package manager owns.
// A "(deleted)" mapping under one of these, whose path has since been re-created
// with a different inode, is a package upgrade — not a dropper. /usr/local is
// deliberately absent: it is admin/attacker-writable and not package-managed, so
// a vanish-and-recreate there stays suspicious.
var packageManagedPrefixes = []string{
	"/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/",
	"/lib/", "/lib64/", "/bin/", "/sbin/",
}

// isDeletedByPackageUpgrade reports whether a "(deleted)" executable mapping is
// the residue of a package upgrade rather than a payload that unlinked itself.
//
// Why this exists: an `apt` upgrade of libc6/openssl unlinks the old inode, so
// EVERY process started before the upgrade keeps mapping it and /proc/<pid>/maps
// reports the library text segment as "(deleted)". On the verification host that
// meant systemd, cron, dbus-daemon, acpid, irqbalance, rsyslogd, docker-proxy and
// the systemd-* daemons were all flagged as "反射型DLL/floating code の可能性" —
// 94 executable (deleted) mappings host-wide, every one of them libc.so.6,
// libm.so.6 or libcrypto.so.3. On Ubuntu with unattended-upgrades this recurs
// after every security update, which buries genuine findings.
//
// The discriminator is inode identity, not the path alone: a package upgrade
// re-creates the path with a NEW inode, while a dropper that unlinks its payload
// leaves nothing behind. Requiring the path to sit under a package-managed prefix
// on top of that keeps the exemption from becoming an evasion — otherwise an
// attacker could drop /tmp/x, exec it, unlink it and touch /tmp/x again to be
// ignored. memfd mappings ("/memfd:name (deleted)") never stat, so they stay
// suspicious, which is the behaviour fileless-exec detection depends on.
func isDeletedByPackageUpgrade(pathname, mapInode string) bool {
	path := strings.TrimSuffix(pathname, " (deleted)")
	if path == pathname || !strings.HasPrefix(path, "/") {
		return false
	}
	if strings.HasPrefix(path, "/usr/local/") {
		return false
	}
	managed := false
	for _, p := range packageManagedPrefixes {
		if strings.HasPrefix(path, p) {
			managed = true
			break
		}
	}
	if !managed {
		return false
	}
	// inode 0 means the kernel reported no backing inode at all — nothing to
	// compare against, so it cannot be shown to be a replacement.
	mapped, err := strconv.ParseUint(mapInode, 10, 64)
	if err != nil || mapped == 0 {
		return false
	}
	current, ok := statInode(path)
	// Path gone => genuinely vanished => keep it suspicious. Path present with
	// the SAME inode should be impossible for a deleted mapping; treat it as
	// suspicious rather than assume a benign race.
	return ok && current != mapped
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
//
// mapInode is the inode column of the maps line; it lets a "(deleted)" mapping
// left behind by a package upgrade be told apart from a self-deleting payload
// (see isDeletedByPackageUpgrade).
func isSuspiciousExecRegion(perms, pathname, mapInode string) (suspicious, rwx, unbacked bool) {
	if !strings.Contains(perms, "x") {
		return false, false, false // only executable regions are injection-relevant
	}
	rwx = strings.Contains(perms, "w")
	backed := strings.HasPrefix(pathname, "/") && !strings.Contains(pathname, "(deleted)")
	if !backed && isDeletedByPackageUpgrade(pathname, mapInode) {
		backed = true
	}
	pseudo := strings.HasPrefix(pathname, "[") // [vdso] / [vsyscall] / [vvar] / [stack]
	unbacked = !backed && !pseudo
	return rwx || unbacked, rwx, unbacked
}

// scanPidMapsStats は 1 プロセスの /proc/<pid>/maps を走査し、疑わしい
// 実行可能領域と、走査したリージョン数・**飛ばした理由**を返す
// (#511 のコスト計上)。
//
// **以前は「読めなかった」の1つにまとめていました。** このコメント自身が
// 「権限不足か、走査中にプロセスが終了したこと」と書いていたとおり、
// 中身は2つです。プロセスは走査中に普通に終了するので、混ぜると
// SkippedUnreadable が健全な端末でも毎周期ゼロにならず、**「中を見られて
// いない端末」の判定に使えません。** 実際どこも判定していませんでした。
//
// 以前は戻り値を findings だけに絞った scanPidMaps という薄いラッパが
// 併存していたが、呼び出し元が無くなっており staticcheck に U1000 で
// 検出されていたため削除した。
// scanPidMapsStatsFn は差し替え可能です。**この端末（root, Linux）では
// 74 件を列挙して 74 件とも走査でき、断られたものがありません。**
// 実環境が必ず成功する条件では、数え分けの分岐を一度も通れません ——
// 変異が1件生き残って分かりました。
//
// 既定が本物であることは `TestTheDefaultMapsScannerIsTheRealOne` が
// 留めます。
var scanPidMapsStatsFn = scanPidMapsStats

func scanPidMapsStats(pid int, name string) (findings []MemoryFinding, regions int, skip skipReason) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, 0, classifySkip(err)
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

		suspicious, rwx, unbacked := isSuspiciousExecRegion(perms, pathname, fields[4])
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
	return out, regions, skipNone
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
