//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// processStatRaw holds raw counters read from /proc for one tick.
type processStatRaw struct {
	pid      int
	name     string
	cpuTotal uint64 // utime + stime in jiffies
	memKB    uint64 // VmRSS in kB (mem == memMeasured のときだけ意味があります)
	mem      memState
}

// readProcessStatsRaw returns raw CPU and memory stats for all running processes
// plus the current total CPU jiffies (for delta calculation).
func readProcessStatsRaw() ([]processStatRaw, uint64, error) {
	totalCPU, err := readTotalCPUJiffies()
	if err != nil {
		return nil, 0, err
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, fmt.Errorf("read /proc: %w", err)
	}

	var stats []processStatRaw
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue // process may have exited
		}
		utime, stime, name, err := parseProcStat(statData)
		if err != nil {
			continue
		}

		// **メモリが読めなくても、この行は出します。**
		//
		// 以前ここは 0 を入れていました。0 は「常駐メモリが無い」という
		// 測定値なので、消えた直後のプロセスが常駐 0 の生きたプロセスに
		// 見えます。そこで前回 continue に変えました —— **それが行き過ぎ
		// でした。** メモリが読めなかったことを理由に、同じ行で読めていた
		// CPU まで捨てています。
		//
		// このコンテナで測った実数: /proc の PID 75 件のうち、
		// **readProcessStatsRaw が返すのは 8 件**でした。落ちた 67 件は
		// すべて「VmRSS 行が無い」= カーネルスレッドで、stat は全件
		// 読めています。**この一覧は CryptoMinerScorer (T1496) の入力です。**
		//
		// メモリは測れた/測れないを型で持ち、`mem_mb` として出るのは
		// 測れたときだけです。
		memKB, mem := readVmRSSFn(pid)
		stats = append(stats, processStatRaw{
			pid:      pid,
			name:     name,
			cpuTotal: utime + stime,
			memKB:    memKB,
			mem:      mem,
		})
	}
	return stats, totalCPU, nil
}

// parseProcStat extracts utime, stime, and comm from /proc/{pid}/stat content.
func parseProcStat(data []byte) (utime, stime uint64, name string, err error) {
	s := string(data)
	start := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if start < 0 || end < 0 || end <= start {
		return 0, 0, "", fmt.Errorf("invalid stat format")
	}
	name = s[start+1 : end]
	rest := s[end+2:] // skip ') '
	fields := strings.Fields(rest)
	// Fields after state: (field 3 onward in spec)
	// Index 11 in rest = utime (spec field 14), index 12 = stime (spec field 15)
	if len(fields) < 13 {
		return 0, 0, name, fmt.Errorf("too few fields")
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	return utime, stime, name, nil
}

// readVmRSSFn は差し替え可能です。**読めない PID を実機で作れない**ので、
// 「読めなかったら飛ばす」の側を検査から通せません。ディスクと CPU の
// 測定関数と同じ扱いにします。
var readVmRSSFn = readVmRSS

// readVmRSS reads resident memory size (kB) from /proc/{pid}/status.
//
// **答えは3つあります。** 「読めた」「読めなかった」の2つに畳むと、
// 3つ目が2つ目に混ざって行ごと消えます:
//
//   - 数値が取れた                  → memMeasured
//   - VmRSS の行が無い              → memNoUserSpace（カーネルスレッド）
//   - 開けない / 数値として読めない → memUnknown
//
// **VmRSS 行が無いのは失敗ではありません。** ユーザ空間を持たないという
// 事実で、CPU は普通に回っています。ここを失敗と同じ扱いにしていたため、
// このコンテナでは 75 件中 67 件が一覧から消えていました。
//
// 途中で消えたプロセスは status が切れて「VmRSS 行が無い」のと同じ姿に
// なります。**scanner.Err() を見ないと、消えたプロセスがカーネル
// スレッドに化けます。**
func readVmRSS(pid int) (uint64, memState) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G304 -- /proc path
	if err != nil {
		return 0, memUnknown
	}
	defer f.Close()
	return parseVmRSS(f)
}

// parseVmRSS is the reading half, split out so every outcome can be reached.
//
// **開くところと読むところが同じ関数だと、壊れた行や途中で切れた
// status を検査から作れません。** 実機の /proc は常に整形された内容を
// 返すので、その分岐は一度も通りません —— 変異が3件生き残って
// 分かりました（`scripts/mutations/process_stats_coverage.py`）。
func parseVmRSS(r io.Reader) (uint64, memState) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, memUnknown
		}
		kb, perr := strconv.ParseUint(fields[1], 10, 64)
		if perr != nil {
			return 0, memUnknown
		}
		return kb, memMeasured
	}
	// **読み切れなかったのと、VmRSS が無いのは別です。** 途中で消えた
	// プロセスの status は切れて、行が無いのと同じ姿になります。
	// ここを見ないと、消えたプロセスがカーネルスレッドに化けます。
	if scanner.Err() != nil {
		return 0, memUnknown
	}
	return 0, memNoUserSpace
}

// readTotalCPUJiffies reads aggregate CPU jiffies from /proc/stat.
func readTotalCPUJiffies() (uint64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		var total uint64
		for i := 1; i < len(fields); i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			total += v
		}
		return total, nil
	}
	return 0, fmt.Errorf("/proc/stat: cpu line not found")
}
