package collector

import (
	"log/slog"
	"syscall"

	"github.com/edr-platform/agent/internal/hostmetrics"
)

// readCPUStat returns the system-wide CPU counters on macOS.
//
// **読み取りは internal/hostmetrics に1本化しました。** 以前はここと
// hostmetrics に別々の仮実装があり、片方を直しても、もう片方は
// 気づかれないまま残る形でした。
//
// macOS の CPU はまだ測れません（理由は hostmetrics/cpu_darwin.go）。
// 測れない間は (0, 0) を返し、呼び出し側は差が取れないので CPUPercent を
// 立てず、スナップショットから欄ごと落ちます —— **0% にはなりません。**
func readCPUStat() (idle, total uint64) {
	idle, total, ok := hostmetrics.SystemCPUCounters()
	if !ok {
		return 0, 0
	}
	return idle, total
}

// readDiskFreeGB returns free disk space in GB for the root filesystem on macOS,
// and whether it could be measured.
func readDiskFreeGB() (float64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		// **0 は「測れなかった」ではなく「空きが全く無い」と読めます。**
		slog.Warn("ディスク空き容量を測れませんでした。この回は報告しません",
			"error", err)
		return 0, false
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	return float64(freeBytes) / (1024 * 1024 * 1024), true
}
