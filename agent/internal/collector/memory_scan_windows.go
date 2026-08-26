//go:build windows

// memory_scan_windows.go implements M1 region enumeration on Windows: walk each
// process's address space with VirtualQueryEx and flag RWX
// (PAGE_EXECUTE_READWRITE / WRITECOPY) and unbacked-executable (MEM_PRIVATE)
// committed regions — the Windows analog of the Linux /proc/maps scan. Reading
// other processes' regions needs SeDebugPrivilege; processes that can't be opened
// are skipped (the agent's own process is always scannable). Pure user mode.
package collector

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	syswin "golang.org/x/sys/windows"
)

const (
	memCommit  = 0x1000
	memPrivate = 0x20000 // MEM_PRIVATE — not image/file backed

	pageExecute          = 0x10
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
	pageExecuteAny       = pageExecute | pageExecuteRead | pageExecuteReadWrite | pageExecuteWriteCopy

	// pageGuard marks a one-shot guard page (stack growth, custom guards). Never
	// content-scan one — see shouldContentScan.
	pageGuard = 0x100

	processQueryInformation = 0x0400
	processVMRead           = 0x0010
)

// memoryBasicInformation mirrors Win32 MEMORY_BASIC_INFORMATION (x64 layout).
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

var (
	modkernel32           = syswin.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx    = modkernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")
)

func virtualQueryEx(h syswin.Handle, addr uintptr, mbi *memoryBasicInformation) bool {
	r, _, _ := procVirtualQueryEx.Call(
		uintptr(h), addr, uintptr(unsafe.Pointer(mbi)), unsafe.Sizeof(*mbi))
	return r != 0
}

// readRegion reads up to maxRegionScanBytes from [base, base+size) of the process
// behind h, which must have been opened with PROCESS_VM_READ. Best-effort: a
// partial read is returned as-is (an implant header at the start of the region is
// still matchable), and a failed read yields nil.
func readRegion(h syswin.Handle, base, size uintptr) []byte {
	if size == 0 {
		return nil
	}
	if size > maxRegionScanBytes {
		size = maxRegionScanBytes
	}
	buf := make([]byte, size)
	var read uintptr
	r, _, _ := procReadProcessMemory.Call(
		uintptr(h), base, uintptr(unsafe.Pointer(&buf[0])), size,
		uintptr(unsafe.Pointer(&read)))
	// ReadProcessMemory returns 0 on a fully failed read, but also reports a
	// partial count when the range straddles unreadable pages — keep whatever
	// was actually copied.
	if read == 0 {
		if r == 0 {
			return nil
		}
		return nil
	}
	if read > size {
		read = size // defensive: never slice past the buffer
	}
	return buf[:read]
}

// ScanProcessMemory scans a single process's memory (used for M2 correlation:
// after an injection operation, check whether the target now has a suspicious
// RWX/unbacked region — the operation plus the resulting artifact = high
// confidence). The allowlist is intentionally bypassed (a specific target).
func ScanProcessMemory(pid int) []MemoryFinding {
	if pid <= 0 {
		return nil
	}
	return scanProcessMemory(uint32(pid), "")
}

// ScanSuspiciousMemory enumerates committed executable memory of every openable
// process, flagging RWX and unbacked-executable regions.
func ScanSuspiciousMemory() []MemoryFinding {
	findings, _ := scanSuspiciousMemoryStats(nil)
	return findings
}

// scanSuspiciousMemoryStats is ScanSuspiciousMemory with the per-cycle
// cost accounting for the #511 load review (see MemoryScanStats). On Windows
// SkippedUnreadable is expected to be large without SeDebugPrivilege: system
// processes cannot be opened at all, so they cost only a failed OpenProcess.
func scanSuspiciousMemoryStats(scan func([]byte) []string) ([]MemoryFinding, MemoryScanStats) {
	var st MemoryScanStats
	procs := enumProcesses()
	st.ProcessesEnumerated = len(procs)
	var findings []MemoryFinding
	for _, p := range procs {
		if isMemoryScanAllowlisted(strings.ToLower(p.name)) {
			st.SkippedAllowlisted++
			continue
		}
		procStart := time.Now()
		f, cost, skip := scanProcessMemoryStats(p.pid, p.name, scan)
		switch skip {
		case skipDenied:
			// **開こうとして断られました。** この中は見ていません。
			// SeDebugPrivilege の無い端末では、ここがほぼ全部です。
			st.SkippedUnreadable++
			continue
		case skipGone:
			// 走査するまでに終了していました。**正常です。**
			st.SkippedGone++
			continue
		}
		st.observeProcess(int(p.pid), p.name, cost.regions, time.Since(procStart))
		st.RegionsYARAScanned += cost.yaraRegions
		st.BytesYARAScanned += cost.yaraBytes
		findings = append(findings, f...)
	}
	st.RawFindings = len(findings)
	return findings, st
}

type winProc struct {
	pid  uint32
	name string
}

func enumProcesses() []winProc {
	snap, err := syswin.CreateToolhelp32Snapshot(syswin.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syswin.CloseHandle(snap)

	var e syswin.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := syswin.Process32First(snap, &e); err != nil {
		return nil
	}
	var out []winProc
	for {
		out = append(out, winProc{pid: e.ProcessID, name: syswin.UTF16ToString(e.ExeFile[:])})
		if err := syswin.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out
}

func scanProcessMemory(pid uint32, name string) []MemoryFinding {
	out, _, _ := scanProcessMemoryStats(pid, name, nil)
	return out
}

// procScanCost is one process's contribution to a cycle's cost.
type procScanCost struct {
	regions     int
	yaraRegions int
	yaraBytes   int64
}

// scanProcessMemoryStats is scanProcessMemory plus per-process cost accounting
// and, when scan is non-nil, in-memory YARA over each RWX region's bytes.
// skip != skipNone means the process was not walked: skipDenied is no access
// (a system process without SeDebugPrivilege — **its contents were not
// looked at**), skipGone is a process that had already exited. They are
// counted separately because only the first is a blind spot; conflating them
// made the number unusable for deciding whether a host can see anything, or
// one that exited mid-scan.
//
// Content scanning happens here, while the process handle is already open,
// rather than in a second pass: reopening the process per region would cost an
// extra OpenProcess for every RWX region, and the MEMORY_BASIC_INFORMATION
// needed to exclude guard pages is only available inside this walk.
func scanProcessMemoryStats(pid uint32, name string, scan func([]byte) []string) (findings []MemoryFinding, cost procScanCost, skip skipReason) {
	if pid == 0 {
		return nil, cost, skipGone // System Idle Process。開く対象ではありません
	}
	// Ask for VM_READ so region contents can be scanned, but fall back to
	// query-only access when it is refused: losing content scanning for one
	// process is far better than losing that process from enumeration entirely.
	access := uint32(processQueryInformation | processVMRead)
	h, err := syswin.OpenProcess(access, false, pid)
	canRead := err == nil
	if err != nil {
		h, err = syswin.OpenProcess(processQueryInformation, false, pid)
		if err != nil {
			// **断られたのか、もう居ないのか。** SeDebugPrivilege が
			// 無い端末ではシステムプロセスがほぼ全部ここに来ます ——
			// その中は見ていません。走査中に終了したプロセスと同じ数に
			// 入れると、その区別がつかなくなります。
			return nil, cost, classifySkip(err)
		}
	}
	defer syswin.CloseHandle(h)

	var out []MemoryFinding
	var addr uintptr
	for {
		var mbi memoryBasicInformation
		if !virtualQueryEx(h, addr, &mbi) {
			break
		}
		cost.regions++
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break // no progress — avoid infinite loop
		}
		addr = next

		if mbi.State != memCommit || mbi.Protect&pageExecuteAny == 0 {
			continue // not committed-executable
		}
		// Mask off modifier bits (PAGE_GUARD 0x100 / PAGE_NOCACHE 0x200 /
		// PAGE_WRITECOMBINE 0x400) so a guarded/non-cached RWX region still matches.
		prot := mbi.Protect & 0xFF
		rwx := prot == pageExecuteReadWrite || prot == pageExecuteWriteCopy
		unbacked := mbi.Type == memPrivate
		if !rwx && !unbacked {
			continue
		}
		perms := "EXEC"
		if rwx {
			perms = "RWX"
		}
		f := MemoryFinding{
			PID:         int(pid),
			ProcessName: name,
			Address:     fmt.Sprintf("%x-%x", mbi.BaseAddress, mbi.BaseAddress+mbi.RegionSize),
			Perms:       perms,
			Size:        uint64(mbi.RegionSize),
			Unbacked:    unbacked,
			RWX:         rwx,
			Reason:      classifyRegion(rwx, unbacked),
		}

		// Content-scan the region with the CURATED in-memory ruleset. This is
		// what makes the Cobalt Strike / Meterpreter / Mimikatz / Havoc markers
		// reachable on Windows at all — enumeration alone only says "a region
		// looks structurally odd", never "this is a known implant".
		if scan != nil && canRead && shouldContentScan(rwx, mbi.Protect&pageGuard != 0) {
			if data := readRegion(h, mbi.BaseAddress, mbi.RegionSize); len(data) > 0 {
				cost.yaraRegions++
				cost.yaraBytes += int64(len(data))
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
		out = append(out, f)
	}
	return out, cost, skipNone
}

// ScanSuspiciousMemoryWithYARA is ScanSuspiciousMemory plus content inspection:
// each RWX region's bytes are read with ReadProcessMemory and run through scan
// (the curated in-memory matcher). A hit escalates the finding and bypasses the
// size floor, so a small but distinctive implant still reports. Guard pages are
// enumerated but never read — see shouldContentScan.
func ScanSuspiciousMemoryWithYARA(scan func([]byte) []string) []MemoryFinding {
	out, _ := ScanSuspiciousMemoryWithYARAStats(scan)
	return out
}

// ScanSuspiciousMemoryWithYARAStats is ScanSuspiciousMemoryWithYARA plus the
// per-cycle cost accounting for the #511 review and later host diagnosis (see
// MemoryScanStats).
func ScanSuspiciousMemoryWithYARAStats(scan func([]byte) []string) ([]MemoryFinding, MemoryScanStats) {
	start := time.Now()
	raw, st := scanSuspiciousMemoryStats(scan)
	out := make([]MemoryFinding, 0, len(raw))
	for _, f := range raw {
		if shouldEmitMemoryFinding(f) {
			out = append(out, f)
		}
	}
	st.EmittedFindings = len(out)
	st.Duration = time.Since(start)
	// **走査できなかったことを、端末の外に出します。** Windows では
	// SeDebugPrivilege が無いとシステムプロセスがほぼ全部ここに落ちます。
	st.report()
	return out, st
}
