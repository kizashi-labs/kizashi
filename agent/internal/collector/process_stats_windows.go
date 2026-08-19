//go:build windows

package collector

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processStatRaw holds raw counters for one tick.
type processStatRaw struct {
	pid      int
	name     string
	cpuTotal uint64 // cumulative CPU time (kernel+user) in centiseconds
	memKB    uint64 // working-set size in kB (mem == memMeasured のときだけ)
	mem      memState
}

var (
	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")

	// procStatsEpochWin anchors the monotonic elapsed counter used to derive the
	// system-wide CPU capacity total. Only differences between readings matter.
	procStatsEpochWin = time.Now()
)

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS (psapi.h); only
// workingSetSize is used (resident memory).
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

// readProcessStatsRaw returns per-process CPU and memory stats on Windows plus a
// system-wide CPU counter for delta calculation. It enumerates processes via a
// Toolhelp32 snapshot (no CGo) and reads each one's kernel+user CPU time
// (GetProcessTimes) and working-set size (GetProcessMemoryInfo). Previously this
// returned an empty slice, so per-process CPU/memory anomaly detection (e.g.
// cryptominers) had zero signal on Windows.
//
// cpuTotal is cumulative CPU time in centiseconds. The returned total is
// NumCPU * monotonic-elapsed-centiseconds — the total CPU time available across
// all cores in the same unit — so the collector's deltaCPU/deltaTotal ratio
// yields the same fraction-of-capacity semantics as the /proc-based Linux path.
func readProcessStatsRaw() ([]processStatRaw, uint64, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, 0, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, 0, err
	}

	var stats []processStatRaw
	for {
		if pid := pe.ProcessID; pid != 0 {
			if st, ok := readOneProcess(pid, windows.UTF16ToString(pe.ExeFile[:])); ok {
				stats = append(stats, st)
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}

	totalCentis := uint64(runtime.NumCPU()) * uint64(time.Since(procStatsEpochWin)/(10*time.Millisecond))
	return stats, totalCentis, nil
}

// readOneProcess opens the process and reads its CPU time and working set.
// Returns ok=false when the process can't be opened (protected / already gone).
func readOneProcess(pid uint32, name string) (processStatRaw, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return processStatRaw{}, false
	}
	defer windows.CloseHandle(h)

	st := processStatRaw{pid: int(pid), name: name}

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err == nil {
		st.cpuTotal = filetimeSumCentis(kernel, user)
	}

	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	ret, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb))
	if ret != 0 {
		st.memKB = uint64(pmc.workingSetSize) / 1024
		st.mem = memMeasured
	}
	// 失敗したときは mem を触りません。**memState の零値は memUnknown です**
	// —— 触り忘れたフィールドが「測った 0」になる向きには倒れません。
	return st, true
}

// filetimeSumCentis converts the kernel+user CPU FILETIMEs (100-ns units) into
// centiseconds — the unit the collector's delta math shares across platforms.
//
// The raw 100-ns units are assembled by hand rather than via Filetime.Nanoseconds():
// that helper treats a FILETIME as an ABSOLUTE timestamp (ticks since 1601-01-01)
// and subtracts the Unix-epoch offset 116444736000000000. GetProcessTimes returns
// kernel/user times as DURATIONS, not absolute timestamps, so the subtraction
// underflows to a huge negative value and every process reported cpuTotal=0 —
// per-process CPU stats on Windows were dead across the board.
func filetimeSumCentis(kernel, user windows.Filetime) uint64 {
	units := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	units += uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	// 1 centisecond = 10 ms = 100,000 units of 100 ns.
	return units / 1e5
}
