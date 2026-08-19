package hostmetrics

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 測れなかったときに 0 を返さないこと。
//
// ハートビートの CPU は全プラットフォームで `return 0.0` の仮実装でした。
// サーバはそれを `agents.cpu_usage` に書き、フリート健全性アラータが
// `COALESCE(cpu_usage, 0) > 閾値` で見ます。**全端末が恒久的に 0% なので、
// 高CPUのアラートは一度も発火できません。**
//
// 0 は測定値として最も安全な顔をしています。高CPUを探す側からは
// 「問題なし」に見えるので、**測っていないことが「異常なし」に化けます。**

func scanOf(s string) *bufio.Scanner { return bufio.NewScanner(strings.NewReader(s)) }

func TestParsesTheAggregateLine(t *testing.T) {
	idle, total, ok := parseProcStat(scanOf(
		"cpu  100 20 30 400 50 6 7 8 0 0\ncpu0 1 2 3 4 5 6 7 8 0 0\n"))
	if !ok {
		t.Fatal("読めていません")
	}
	// idle = idle(400) + iowait(50)
	if idle != 450 {
		t.Errorf("idle = %d, want 450", idle)
	}
	if total != 100+20+30+400+50+6+7+8 {
		t.Errorf("total = %d", total)
	}
}

// 途中の数値が壊れていたら、**部分的に足した合計を返さないこと。**
// 返すと、0 と同じ種類の嘘（それらしい数値）になります。
func TestABrokenFieldIsNotAPartialTotal(t *testing.T) {
	if _, _, ok := parseProcStat(scanOf("cpu  100 20 xx 400 50 6\n")); ok {
		t.Error("壊れた行を読めたことにしています")
	}
}

// 欄が足りない行は使えないこと。idle と iowait が揃わなければ
// 利用率は出せません。
func TestATruncatedLineIsNotUsable(t *testing.T) {
	if _, _, ok := parseProcStat(scanOf("cpu  100 20 30\n")); ok {
		t.Error("欄の足りない行を読めたことにしています")
	}
}

// 集計行が無ければ、測れていないこと。
func TestNoAggregateLineIsNotMeasured(t *testing.T) {
	if _, _, ok := parseProcStat(scanOf("cpu0 1 2 3 4 5 6\nintr 12345\n")); ok {
		t.Error("cpu 行が無いのに読めたことにしています")
	}
}

func TestAMissingFileIsNotMeasured(t *testing.T) {
	if _, _, ok := readProcStat(filepath.Join(t.TempDir(), "nope")); ok {
		t.Error("存在しないファイルを読めたことにしています")
	}
}

// 最初の1回は差が取れないので、「測れなかった」で返すこと。
// **0% として返すと、起動直後の端末が全部アイドルに見えます。**
func TestTheFirstSampleHasNoDelta(t *testing.T) {
	s := &CPUSampler{} // 未 prime
	if pct, ok := s.percentFrom(100, 1000); ok {
		t.Errorf("最初の1回で %v%% を返しています。差が取れていません", pct)
	}
	// prime されたので、2回目からは測れること。
	if _, ok := s.percentFrom(150, 1200); !ok {
		t.Error("2回目でも測れないと言っています")
	}
}

// カウンタが進んでいなければ、測れていないこと。
// 巻き戻り（コンテナ再作成など）でも同じです。
func TestNoProgressIsNotZeroPercent(t *testing.T) {
	// total が同じ ＝ 差が無い
	s := &CPUSampler{haveSample: true, prevIdle: 100, prevTotal: 1000}
	if pct, ok := s.percentFrom(100, 1000); ok {
		t.Errorf("差が無いのに %v%% を返しています", pct)
	}
	// 巻き戻り（毎回 prev が更新されるので、状態を作り直します）
	s = &CPUSampler{haveSample: true, prevIdle: 100, prevTotal: 1000}
	if pct, ok := s.percentFrom(50, 500); ok {
		t.Errorf("巻き戻ったのに %v%% を返しています", pct)
	}
}

// idle の伸びが total の伸びを超えたら、使用率を出さないこと。
// **uint の引き算なので、出すと巨大な正の数に化けます。**
func TestImpossibleIdleGrowthIsNotMeasured(t *testing.T) {
	s := &CPUSampler{haveSample: true, prevIdle: 100, prevTotal: 1000}
	if pct, ok := s.percentFrom(900, 1100); ok {
		t.Errorf("あり得ない差なのに %v%% を返しています", pct)
	}
}

// 差が取れれば、利用率を返すこと。**測れるときに測れないと言うのも嘘です。**
func TestAProperDeltaIsMeasured(t *testing.T) {
	s := &CPUSampler{haveSample: true, prevIdle: 100, prevTotal: 1000}
	pct, ok := s.percentFrom(150, 1200) // idle +50, total +200 → 75% busy
	if !ok {
		t.Fatal("測れたはずです")
	}
	if pct < 74.9 || pct > 75.1 {
		t.Errorf("pct = %v, want 75", pct)
	}
}

// **ここには計算の写しがありました。** 変異で本体の判定を緩めても写しは
// 無傷なので、何も落ちませんでした —— 検査していたのは検査自身の写しです。
// いまは percentFrom（本体）を直接呼びます。

// 既定の測定関数が、本物を指していること。
//
// **これが無いと、既定をスタブに差し替える変異が生き残ります。**
// 実際に生き残りました —— どの検査も自分で差し替えるので、既定が
// 何であっても通ります。
func TestTheDefaultReaderIsTheRealOne(t *testing.T) {
	// /proc/stat のある環境なら、素の readCPUStat が測れること。
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("/proc/stat がありません")
	}
	if _, _, ok := readCPUStat(); !ok {
		t.Error("/proc/stat があるのに測れないと言っています")
	}
}

// ─── メモリ ─────────────────────────────────────────────────────────────

// used は MemTotal − MemAvailable であること。**MemFree ではありません。**
//
// ページキャッシュは「使用中」ではなく、必要になれば回収されます。
// MemFree で引くと、健全な Linux 端末がほぼ全部メモリ逼迫に見えます。
func TestUsedMemoryIsTotalMinusAvailable(t *testing.T) {
	total, avail, ok := parseMemInfo(scanOf(
		"MemTotal:       8000000 kB\nMemFree:          100000 kB\n" +
			"MemAvailable:   6000000 kB\nBuffers:          50000 kB\n"))
	if !ok {
		t.Fatal("読めていません")
	}
	if total != 8000000 || avail != 6000000 {
		t.Errorf("(total, avail) = (%d, %d)", total, avail)
	}
	// MemFree(100000) を使っていたら used は 7.9GB 近くになります。
	if used := total - avail; used != 2000000 {
		t.Errorf("used = %d kB, want 2000000。MemFree で引いていませんか", used)
	}
}

// MemAvailable の無い古いカーネルでは、推定せずに「測れなかった」と言うこと。
// **推定して出すと、0 と同じ種類の嘘になります。**
func TestMissingMemAvailableIsNotMeasured(t *testing.T) {
	if _, _, ok := parseMemInfo(scanOf(
		"MemTotal:       8000000 kB\nMemFree:          100000 kB\n")); ok {
		t.Error("MemAvailable が無いのに測れたことにしています")
	}
}

func TestMissingMemTotalIsNotMeasured(t *testing.T) {
	if _, _, ok := parseMemInfo(scanOf("MemAvailable:   6000000 kB\n")); ok {
		t.Error("MemTotal が無いのに測れたことにしています")
	}
}

// あり得ない値（利用可能 > 総容量、総容量 0）は使わないこと。
func TestImpossibleMemoryValuesAreNotMeasured(t *testing.T) {
	if _, _, ok := parseMemInfo(scanOf(
		"MemTotal:       1000 kB\nMemAvailable:   9000 kB\n")); ok {
		t.Error("利用可能が総容量を超えているのに測れたことにしています")
	}
	if _, _, ok := parseMemInfo(scanOf(
		"MemTotal:             0 kB\nMemAvailable:        0 kB\n")); ok {
		t.Error("総容量 0 を測れたことにしています")
	}
}

func TestABrokenMemInfoValueIsNotMeasured(t *testing.T) {
	if _, _, ok := parseMemInfo(scanOf(
		"MemTotal:       xxxx kB\nMemAvailable:   6000000 kB\n")); ok {
		t.Error("読めない数値を測れたことにしています")
	}
}

func TestAMissingMemInfoFileIsNotMeasured(t *testing.T) {
	if _, _, ok := readMemInfo(filepath.Join(t.TempDir(), "nope")); ok {
		t.Error("存在しないファイルを読めたことにしています")
	}
}

// kB から MB に直すこと。**桁を間違えると、8GB の端末が 8MB に見えます。**
func TestMemoryIsReportedInMegabytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(path,
		[]byte("MemTotal:       8388608 kB\nMemAvailable:   4194304 kB\n"), 0o600); err != nil {
		t.Fatalf("書けません: %v", err)
	}
	used, total, ok := readMemInfo(path)
	if !ok {
		t.Fatal("読めていません")
	}
	if total != 8192 {
		t.Errorf("total = %v MB, want 8192", total)
	}
	if used != 4096 {
		t.Errorf("used = %v MB, want 4096", used)
	}
}
