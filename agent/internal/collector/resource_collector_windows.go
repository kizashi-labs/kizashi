package collector

import (
	"log/slog"
	"os"

	"github.com/edr-platform/agent/internal/hostmetrics"
	"golang.org/x/sys/windows"
)

// readCPUStat returns the system-wide CPU counters on Windows.
//
// **以前は (0, 0) を返していました。** コメントには "not implemented on
// Windows without cgo" とありましたが、cgo は要りません ——
// `GetSystemTimes` は kernel32 にあり、`internal/hostmetrics` が呼びます。
//
// 呼び出し側 (resource_collector.collect) は差が取れないときに
// CPUPercent を立てないので、測れなければ欄ごと落ちます。
func readCPUStat() (idle, total uint64) {
	idle, total, ok := hostmetrics.SystemCPUCounters()
	if !ok {
		// **0, 0 は「使用率 0%」ではありません。** 呼び出し側は
		// prevTotal == 0 / total <= prevTotal のときに CPUPercent を
		// 立てないので、欄ごと落ちます。
		return 0, 0
	}
	return idle, total
}

// readDiskFreeGB returns free space on the system drive, and whether it could
// be measured.
//
// **以前は常に (0, false) でした。** コメントには "not implemented on
// Windows without cgo" とありましたが、`GetDiskFreeSpaceEx` は
// x/sys/windows にあります。**Windows の端末はディスク空き容量を一度も
// 報告していませんでした。**
//
// 見るのは呼び出し側に利用可能な量 (freeBytesAvailableToCaller) です ——
// クォータのある環境では、ボリュームの空き合計より少なくなります。
// 書ける量の方が、端末の状態として正しい数字です。
func readDiskFreeGB() (float64, bool) {
	root, err := windows.UTF16PtrFromString(systemDriveRoot())
	if err != nil {
		slog.Warn("ディスク空き容量を測れませんでした。この回は報告しません",
			"error", err)
		return 0, false
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(root, &freeToCaller, &totalBytes, &totalFree); err != nil {
		// **0 は「測れなかった」ではなく「満杯」と読めます。**
		slog.Warn("ディスク空き容量を測れませんでした。この回は報告しません",
			"error", err)
		return 0, false
	}
	return float64(freeToCaller) / (1024 * 1024 * 1024), true
}

// systemDriveRoot returns the root of the drive Windows is installed on.
//
// **`C:\` を決め打ちしません。** SystemDrive が D: の端末はあり、
// その場合 C: を測ると「別のボリュームの空き」を端末の空き容量として
// 報告します。取れなければ C: に戻します。
func systemDriveRoot() string {
	// **`os.Getenv` で1箇所にしてあります。** 同じ名前を2回書くと、
	// 片方だけ間違えた変異が検査をすり抜けます（実際にすり抜けました）。
	if d := os.Getenv("SystemDrive"); d != "" {
		return d + `\`
	}
	return `C:\`
}
