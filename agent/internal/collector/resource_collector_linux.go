package collector

import (
	"bufio"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// readCPUStat reads the aggregate CPU counters from /proc/stat.
// Returns (idle, total) jiffies since boot.
// On any error it returns (0, 0), causing the CPU% to be reported as 0.
func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		// cpu  user nice system idle iowait irq softirq steal guest guest_nice
		fields := strings.Fields(line)
		// fields[0] == "cpu", fields[1..] are the counters
		if len(fields) < 5 {
			return 0, 0
		}
		var values [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			values[i-1] = v
			total += v
		}
		// idle is field index 3 (0-based among the counters), iowait is index 4
		idle = values[3] + values[4]
		return idle, total
	}
	return 0, 0
}

// readDiskFreeGB returns the free disk space in GB for the root filesystem,
// and whether it could be measured.
func readDiskFreeGB() (float64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		// **0 は「測れなかった」ではなく「空きが全く無い」と読めます。**
		// 測定の失敗が、いちばん深刻な観測値になります。
		slog.Warn("ディスク空き容量を測れませんでした。この回は報告しません",
			"error", err)
		return 0, false
	}
	// Bavail: blocks available to unprivileged users; Bsize: block size in bytes
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	return float64(freeBytes) / (1024 * 1024 * 1024), true
}
