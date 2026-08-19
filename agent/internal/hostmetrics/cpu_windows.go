//go:build windows

package hostmetrics

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows の CPU とメモリ。**cgo は要りません。**
//
// このファイルが置き換えた `cpu_other.go` の版は、Windows で
// `(0, 0, false)` を返していました。false なので 0% の嘘にはなりません
// —— **ただし、Windows の端末は CPU とメモリを一度も報告しません。**
// フリート健全性アラータの CPU 判定とメモリ判定は、Windows 端末に対して
// 一度も発火できませんでした。
//
// `GetSystemTimes` と `GlobalMemoryStatusEx` は kernel32 にあり、
// x/sys/windows には包みがないので LazyDLL で直に呼びます
// （`internal/collector/process_stats_windows.go` の psapi と同じやり方）。
//
// **算術は platform_math.go にあります。** syscall そのものはこの端末で
// 確かめられませんが、間違えるのは算術の側です。
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors MEMORYSTATUSEX. Length must be set before the call.
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func readCPUStat() (idle, total uint64, ok bool) {
	var idleFT, kernelFT, userFT windows.Filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleFT)),
		uintptr(unsafe.Pointer(&kernelFT)),
		uintptr(unsafe.Pointer(&userFT)),
	)
	if r == 0 {
		return 0, 0, false
	}
	return windowsCPUTotals(
		ftTicks(idleFT.HighDateTime, idleFT.LowDateTime),
		ftTicks(kernelFT.HighDateTime, kernelFT.LowDateTime),
		ftTicks(userFT.HighDateTime, userFT.LowDateTime),
	)
}

func readMemory() (usedMB, totalMB float64, ok bool) {
	var st memoryStatusEx
	st.length = uint32(unsafe.Sizeof(st))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return 0, 0, false
	}
	return windowsMemoryMB(st.totalPhys, st.availPhys)
}
