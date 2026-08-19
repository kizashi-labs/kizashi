package hostmetrics

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"strings"
)

// このファイルに build tag はありません。**意図です。**
//
// Windows と macOS の読み取りは、この端末では走らせられません。syscall や
// 外部コマンドの呼び出しそのものは確かめようがありませんが、**間違える
// のはほとんど算術と解析の側です。** そこを OS 非依存の関数に出して、
// Linux の CI で通します。
//
// このリポジトリには前例があります。`process_stats_windows.go` の
// `filetimeSumCentis` は、FILETIME を絶対時刻として扱う Go の
// `Filetime.Nanoseconds()` を使っていたため、**全プロセスの CPU 時間が
// 0 になっていました。** 呼び出しは成功し、型は合い、値だけが嘘でした。
// 「Windows でしか確かめられない」は「確かめていない」になります。

// ── Windows ──────────────────────────────────────────────────────────────

// ftTicks combines a FILETIME's two halves into 100ns ticks.
//
// **Filetime.Nanoseconds() は使えません。** あれは FILETIME を
// 1601-01-01 起点の絶対時刻として扱い、Unix エポック分を引きます。
// GetSystemTimes が返すのは経過時間なので、引くと桁が飛びます。
func ftTicks(high, low uint32) uint64 {
	return uint64(high)<<32 | uint64(low)
}

// windowsCPUTotals derives (idle, total) from GetSystemTimes' three FILETIMEs.
//
// **kernel には idle が含まれます。** MSDN のとおりで、ここを足し忘れると
// 分母が小さくなり、CPU 使用率が実際より高く出ます。したがって
// total = kernel + user、idle はそのまま idle です。
func windowsCPUTotals(idle, kernel, user uint64) (uint64, uint64, bool) {
	total := kernel + user
	// 起動直後にどれかが 0 で返ることがあります。**0% ではなく
	// 「まだ分からない」です。**
	if total == 0 || idle > total {
		return 0, 0, false
	}
	return idle, total, true
}

// windowsMemoryMB derives used/total MB from MEMORYSTATUSEX.
//
// used = 物理合計 − 利用可能。**空き (Free) ではありません** —— Linux 側で
// MemFree ではなく MemAvailable を使っているのと同じ理由で、回収できる分を
// 「使用中」に数えると、健全な端末がほぼ全部メモリ逼迫に見えます。
func windowsMemoryMB(totalPhys, availPhys uint64) (usedMB, totalMB float64, ok bool) {
	if totalPhys == 0 || availPhys > totalPhys {
		return 0, 0, false
	}
	const mb = 1024 * 1024
	return float64(totalPhys-availPhys) / mb, float64(totalPhys) / mb, true
}

// ── macOS ────────────────────────────────────────────────────────────────

// parseVMStat pulls the used-memory page counts out of `vm_stat` output.
//
// used = active + wired + compressor。**inactive は数えません** ——
// 必要になれば回収される分で、Linux の MemAvailable と同じ考え方です。
// 数えると、健全な Mac がほぼ全部メモリ逼迫に見えます。
//
// ページサイズは**見出し行から取ります。**
//
//	Mach Virtual Memory Statistics: (page size of 16384 bytes)
//
// Apple Silicon は 16384 で、Intel は 4096 です。**4096 を決め打ちすると、
// Apple Silicon の使用量が実際の 1/4 になります** —— 呼び出しは成功し、
// 型も合い、値だけが 4 倍ずれます。
func parseVMStat(r io.Reader) (usedBytes uint64, ok bool) {
	sc := bufio.NewScanner(r)
	var pageSize uint64
	var active, wired, compressor uint64
	var haveActive, haveWired bool

	for sc.Scan() {
		line := sc.Text()
		if pageSize == 0 {
			if sz, found := parsePageSize(line); found {
				pageSize = sz
				continue
			}
		}
		key, value, found := parseVMStatLine(line)
		if !found {
			continue
		}
		switch key {
		case "Pages active":
			active, haveActive = value, true
		case "Pages wired down":
			wired, haveWired = value, true
		case "Pages occupied by compressor":
			// 圧縮されたメモリは物理 RAM を占めています。
			compressor = value
		}
	}
	if sc.Err() != nil {
		return 0, false
	}
	// **どれか欠けたら答えません。** 足りない項を 0 として足すと、
	// 部分的な合計が測定値の顔をします。
	if pageSize == 0 || !haveActive || !haveWired {
		return 0, false
	}
	return (active + wired + compressor) * pageSize, true
}

// parsePageSize reads the page size out of vm_stat's header line.
func parsePageSize(line string) (uint64, bool) {
	const marker = "page size of "
	i := strings.Index(line, marker)
	if i < 0 {
		return 0, false
	}
	rest := strings.TrimSpace(line[i+len(marker):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	// 0 を弾く番人はここには置きません。**parseVMStat の
	// `pageSize == 0` が1箇所で見ます。** 二重に置くと、片方を外しても
	// 振る舞いが変わらず、検査で壊れたことに気づけません（変異が
	// 1件生き残って分かりました）。
	return v, true
}

// parseVMStatLine splits one "Pages active:  56789." line.
func parseVMStatLine(line string) (key string, value uint64, ok bool) {
	i := strings.LastIndexByte(line, ':')
	if i < 0 {
		return "", 0, false
	}
	key = strings.TrimSpace(line[:i])
	// 値には末尾のピリオドが付きます。
	raw := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[i+1:]), "."))
	if raw == "" {
		return "", 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return key, v, true
}

// parseSysctlUint reads the single number `sysctl -n <key>` prints.
func parseSysctlUint(out []byte) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

// darwinMemoryFrom composes the two macOS readings into MB.
//
// **build tag が無いのは意図です。** `readMemory` の本体をここに置くこと
// で、macOS を走らせられないこの端末でも「vm_stat の出力と sysctl の出力
// から、正しい2つの数が出ること」を通せます。cpu_darwin.go に残るのは
// 2つのコマンドを起動する部分だけです。
func darwinMemoryFrom(vmStatOut, memSizeOut []byte) (usedMB, totalMB float64, ok bool) {
	usedBytes, ok := parseVMStat(bytes.NewReader(vmStatOut))
	if !ok {
		return 0, 0, false
	}
	totalBytes, ok := parseSysctlUint(memSizeOut)
	if !ok {
		return 0, 0, false
	}
	return darwinMemoryMB(usedBytes, totalBytes)
}

// darwinMemoryMB combines the two readings.
//
// **合計だけ、使用量だけ、では出しません。** 片方が測れていないときに
// もう片方を出すと、サーバ側の使用率 (used/total) が壊れます。
func darwinMemoryMB(usedBytes, totalBytes uint64) (usedMB, totalMB float64, ok bool) {
	if totalBytes == 0 || usedBytes > totalBytes {
		return 0, 0, false
	}
	const mb = 1024 * 1024
	return float64(usedBytes) / mb, float64(totalBytes) / mb, true
}
