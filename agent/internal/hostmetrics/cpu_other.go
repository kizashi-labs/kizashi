//go:build !linux && !windows && !darwin

package hostmetrics

// readCPUStat is not implemented on this platform.
//
// **0 ではなく「測れなかった」を返します。** 入れていないことを、
// 0% という測定値に化けさせないのがこのファイルの役目です。
//
// Windows は `cpu_windows.go` が GetSystemTimes で実装しました。macOS の
// CPU はまだここと同じ扱いです（理由は `cpu_darwin.go` にあります）。
// 実装したら、そのプラットフォームを build tag から外してください。
func readCPUStat() (idle, total uint64, ok bool) {
	return 0, 0, false
}

// readMemory is not implemented on this platform.
//
// Windows は `cpu_windows.go` (GlobalMemoryStatusEx)、macOS は
// `cpu_darwin.go` (vm_stat + sysctl hw.memsize) が実装しました。
// **入れていないことを、0 MB という測定値に化けさせません。**
func readMemory() (usedMB, totalMB float64, ok bool) {
	return 0, 0, false
}
