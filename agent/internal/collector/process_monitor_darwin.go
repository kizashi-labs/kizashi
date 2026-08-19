//go:build darwin

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/edr-platform/agent/internal/telemetry"
)

// processListImpl reads /proc on Darwin (macOS).
// Note: macOS does not expose /proc by default. This implementation returns an
// empty list on macOS. A production implementation would use the sysctl
// KERN_PROC_ALL call or the libproc.h API (both require cgo). The stub is
// here to satisfy the build constraint without introducing cgo or syscall
// complexity into the no-cgo agent build.
func processListImpl() ([]ProcessInfo, error) {
	// Attempt /proc first (available on some macOS builds and Docker containers).
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// **「プロセスが0件」ではなく「数えられなかった」です。**
		//
		// このファイルには /proc 以外の経路がありません。macOS の
		// 実機に /proc はないので、**この関数は常に0件を成功として
		// 返していました。** 呼び出し側 (process_monitor.scan) は
		// それを「動いているプロセスは無い」として扱います ——
		// 稼働中の Mac で、あり得ない答えです。
		//
		// エラーを返すと scan は記録して次の周回に回します。0件の
		// 一覧を配るよりは、数えられなかったと言う方が正確です。
		telemetry.Set(sensorMacProcess, telemetry.ModeFailed,
			"/proc がありません（macOS には ps 経由の実装が要ります）")
		return nil, fmt.Errorf("プロセス一覧を取れません: /proc がありません: %w", err)
	}

	var procs []ProcessInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		commPath := filepath.Join("/proc", e.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		procs = append(procs, ProcessInfo{PID: pid, Name: name})
	}
	return procs, nil
}

// sensorMacProcess — ハートビートに載る名前。
const sensorMacProcess = "macos_process"
