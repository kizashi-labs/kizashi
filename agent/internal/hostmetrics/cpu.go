// Package hostmetrics measures the endpoint's own resource usage, and says so
// when it cannot.
//
// **「測れなかった」と「0」を分けるためだけに在ります。** ハートビートの
// CPU 使用率は、全プラットフォームで 0.0 を返す仮実装でした:
//
//	func getCPUUsage() float64 {
//	    // Simplified - real implementation reads /proc/stat on Linux,
//	    // GetSystemTimes on Windows, host_cpu_load_info on macOS
//	    return 0.0
//	}
//
// サーバはこれを `agents.cpu_usage` に書き、フリート健全性アラータが
// `COALESCE(cpu_usage, 0) > 閾値` で見ます。**全端末が恒久的に 0% なので、
// 高CPUのアラートは一度も発火できません。** 「CPU が高い端末は無い」と
// 「CPU を測っていない」が、同じ画面になります。
//
// 0 は測定値として最も安全な顔をしています —— 高CPUを探す側からは
// 「問題なし」に見え、ディスク空き容量なら逆に「満杯」に見えます
// （resource_collector の readDiskFreeGB も同じ形でした）。
// **どちらも、測っていないことを最も強い主張に化けさせます。**
package hostmetrics

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// CPUSampler turns two /proc/stat readings into a utilisation percentage.
//
// 一発では出せません。/proc/stat は起動からの累積 jiffy なので、
// 2点の差が要ります。呼び出し側が状態を持たずに済むよう、ここで持ちます。
type CPUSampler struct {
	mu         sync.Mutex
	haveSample bool
	prevIdle   uint64
	prevTotal  uint64
}

// NewCPUSampler returns a sampler primed with one reading, so the first
// Percent call after an interval already has a delta to work with.
func NewCPUSampler() *CPUSampler {
	s := &CPUSampler{}
	if idle, total, ok := readCPUStat(); ok {
		s.prevIdle, s.prevTotal, s.haveSample = idle, total, true
	}
	return s
}

// Percent returns the CPU utilisation since the previous call, and whether it
// could be measured at all.
//
// **測れなかったときに 0 を返さないのが、この関数の存在理由です。**
// 返り値は (値, 測れたか) で、呼び出し側は測れなかったぶんを送りません。
// 送らなければ、サーバは NULL のままにします。
func (s *CPUSampler) Percent() (float64, bool) {
	idle, total, ok := readCPUStat()
	if !ok {
		return 0, false
	}
	return s.percentFrom(idle, total)
}

// percentFrom is the arithmetic, given one fresh reading.
//
// **検査はこちらを呼びます。** 最初は検査の側に同じ計算を書き写して
// いました。変異で `Percent` の判定を緩めても、写しの方は無傷なので
// **何も落ちませんでした** —— 検査していたのは、検査自身の写しでした。
func (s *CPUSampler) percentFrom(idle, total uint64) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevIdle, prevTotal, primed := s.prevIdle, s.prevTotal, s.haveSample
	s.prevIdle, s.prevTotal, s.haveSample = idle, total, true

	if !primed || total <= prevTotal {
		// まだ差が取れません。**0% ではなく「分からない」です。**
		// カウンタが巻き戻る（コンテナの再作成など）ときも同じ扱いにします。
		return 0, false
	}
	deltaTotal := total - prevTotal
	deltaIdle := idle - prevIdle
	if deltaIdle > deltaTotal {
		return 0, false
	}
	return float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0, true
}

// parseProcStat extracts (idle, total) jiffies from /proc/stat's aggregate line.
//
// 切り出してあるのは、/proc の無い環境でも判定そのものを試せるようにする
// ためです。**「Linux でしか確かめられない」は「確かめていない」になります。**
func parseProcStat(r *bufio.Scanner) (idle, total uint64, ok bool) {
	for r.Scan() {
		line := r.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		// cpu  user nice system idle iowait irq softirq steal guest guest_nice
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return 0, 0, false // idle と iowait が揃わないと使えません
		}
		var values [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				// **1つでも読めなければ、合計は嘘になります。**
				// 部分的に足した値を返すと、0 と同じ種類の嘘になります。
				return 0, 0, false
			}
			values[i-1] = v
			total += v
		}
		return values[3] + values[4], total, true
	}
	return 0, 0, false
}

func readProcStat(path string) (idle, total uint64, ok bool) {
	f, err := os.Open(path) // #nosec G304 -- fixed path from the caller
	if err != nil {
		return 0, 0, false
	}
	defer func() { _ = f.Close() }() // 読み取り専用。閉じる失敗に伝える情報は無い
	return parseProcStat(bufio.NewScanner(f))
}

// Memory reports the endpoint's memory usage and total, both in MB, and
// whether they could be measured.
//
// **エージェント自身の使用量ではありません。** ハートビートは
// `runtime.MemStats.Sys` を送っていました —— Go ランタイムが OS から
// 取った量で、端末のメモリ使用量とは別物です。サーバはそれを
// `agents.memory_usage_mb` に書き、フリート健全性アラータが
// `memory_usage_mb / total_memory_mb * 100` で「端末のメモリ使用率」として
// 見ます。**測れていないのではなく、別のものを測っていました。**
//
// （`internal/resource.Throttle` が同じ `ms.Sys` を見ているのは正しい用途です
// —— あちらはエージェント自身の使用量を上限と比べています。）
//
// total は `agents.total_memory_mb` の書き手でもあります。**いままで誰も
// 書いていなかったので、アラータのメモリ判定は分母が NULL で、
// 一度も発火できませんでした。**
func Memory() (usedMB, totalMB float64, ok bool) {
	return readMemory()
}

// parseMemInfo pulls total and available memory (in kB) out of /proc/meminfo.
//
// used = MemTotal - MemAvailable です。MemFree ではありません ——
// **ページキャッシュは「使用中」ではなく、必要になれば回収されます。**
// MemFree で引くと、健全な Linux 端末がほぼ全部メモリ逼迫に見えます。
func parseMemInfo(r *bufio.Scanner) (totalKB, availKB uint64, ok bool) {
	var haveTotal, haveAvail bool
	for r.Scan() {
		line := r.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB, haveTotal = parseMemInfoValue(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB, haveAvail = parseMemInfoValue(line)
		}
		if haveTotal && haveAvail {
			break
		}
	}
	// **片方だけでは使えません。** MemAvailable の無い古いカーネル
	// (3.14 未満) では、使用量を出せないと言います。推定して出すと、
	// 0 と同じ種類の嘘になります。
	if !haveTotal || !haveAvail || totalKB == 0 || availKB > totalKB {
		return 0, 0, false
	}
	return totalKB, availKB, true
}

func parseMemInfoValue(line string) (uint64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func readMemInfo(path string) (usedMB, totalMB float64, ok bool) {
	f, err := os.Open(path) // #nosec G304 -- fixed path from the caller
	if err != nil {
		return 0, 0, false
	}
	defer func() { _ = f.Close() }() // 読み取り専用。同上
	totalKB, availKB, ok := parseMemInfo(bufio.NewScanner(f))
	if !ok {
		return 0, 0, false
	}
	return float64(totalKB-availKB) / 1024, float64(totalKB) / 1024, true
}

// SystemCPUCounters exposes the platform's cumulative CPU counters.
//
// **`internal/collector` の resource_collector が同じ値を必要としています。**
// あちらは自前の (idle, total) を持っていて、Windows と macOS では
// `(0, 0)` を返す仮実装のままでした —— このパッケージが直したのと同じ
// 穴が、もう一箇所あったことになります。読み取りは1つにします。
func SystemCPUCounters() (idle, total uint64, ok bool) {
	return readCPUStat()
}
