//go:build linux

package collector

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// 常駐メモリを読めなかったプロセスを、0 MB として一覧に載せないこと。
//
// `readVmRSS` は読めないと 0 を返していました。0 は「常駐メモリが無い」
// という測定値なので、消えた直後のプロセスが常駐 0 の生きたプロセスに
// 見えます。
//
// **前回はそれを「行ごと落とす」で直しました。行き過ぎでした。**
// メモリが読めなかったことを理由に、同じ行で読めていた CPU まで捨てて
// います。このコンテナで測った実数は 75 件中 8 件 —— 落ちた 67 件は
// 全部カーネルスレッド（VmRSS 行が無い）で、stat は全件読めていました。
//
// いまは3つを区別します:
//
//	memMeasured    数値が取れた            → mem_mb に出る
//	memNoUserSpace VmRSS 行が無い          → mem_mb は出さない（事実であって失敗ではない）
//	memUnknown     開けない／読めない      → mem_mb は出さない
//
// **行はどれも残ります。** `process_stats` は CryptoMinerScorer (T1496) の
// 入力なので、一覧に出ない PID は CPU を焼き続けても検知されません。

func TestVmRSSForAMissingProcessIsNotZero(t *testing.T) {
	// 存在しない PID。/proc/<pid>/status を開けません。
	if kb, st := readVmRSS(1 << 30); st != memUnknown {
		t.Errorf("存在しない PID を (%d kB, %v) として読めたことにしています", kb, st)
	}
}

// 自分自身は読めること。**塞ぐ側だけ直して、読めるものまで
// 落としていないこと。**
func TestVmRSSForOurselvesIsMeasured(t *testing.T) {
	kb, st := readVmRSS(os.Getpid())
	if st != memMeasured {
		t.Fatalf("自分自身の VmRSS が %v です", st)
	}
	if kb == 0 {
		t.Error("自分自身が 0 kB と出ています")
	}
}

// 不正な PID は「読めない」。**数値として読めない値を 0 にしないこと。**
// 以前は ParseUint のエラーを捨てていました。
func TestAStatusWithoutVmRSSIsNotMeasured(t *testing.T) {
	if kb, st := readVmRSS(-1); st != memUnknown {
		t.Errorf("不正な PID を (%d kB, %v) として読めたことにしています", kb, st)
	}
}

// カーネルスレッドが、この端末に実在すること。
//
// **これが 0 件だと、下の「行が残る」検査は何も確かめていません。**
// 測ったときは 75 件中 67 件でした。
func TestKernelThreadsExistOnThisHost(t *testing.T) {
	stats, _, err := readProcessStatsRaw()
	if err != nil {
		t.Fatalf("readProcessStatsRaw: %v", err)
	}
	var noUser int
	for _, s := range stats {
		if s.mem == memNoUserSpace {
			noUser++
		}
	}
	if noUser == 0 {
		t.Skip("この環境にカーネルスレッドがありません")
	}
	t.Logf("%d 件中 %d 件がユーザ空間を持ちません", len(stats), noUser)
}

// ユーザ空間を持たないタスクも、一覧に残ること。
//
// **CPU は読めています。** メモリが無いことを理由に行ごと落とすと、
// 読めた測定値まで捨てます。
func TestATaskWithoutUserMemoryIsStillListed(t *testing.T) {
	orig := readVmRSSFn
	readVmRSSFn = func(int) (uint64, memState) { return 0, memNoUserSpace }
	t.Cleanup(func() { readVmRSSFn = orig })

	stats, _, err := readProcessStatsRaw()
	if err != nil {
		t.Fatalf("readProcessStatsRaw: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("1件も返っていません。**この一覧は T1496 の入力です** —— " +
			"出ない PID は CPU を焼き続けても検知されません")
	}
	for _, s := range stats {
		if s.mem != memNoUserSpace {
			t.Fatalf("PID %d の mem = %v", s.pid, s.mem)
		}
	}
}

// 読めなかったプロセスも、一覧に残ること。ただし**メモリは出さないこと。**
//
// **読めない PID を実機で作れない**ので、読み取りを差し替えて確かめます。
func TestAnUnreadableProcessKeepsItsCPUButNotItsMemory(t *testing.T) {
	orig := readVmRSSFn
	readVmRSSFn = func(int) (uint64, memState) { return 0, memUnknown }
	t.Cleanup(func() { readVmRSSFn = orig })

	stats, _, err := readProcessStatsRaw()
	if err != nil {
		t.Fatalf("readProcessStatsRaw: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("1件も返っていません")
	}
	for _, s := range stats {
		if v := memMB(s.memKB, s.mem); v != nil {
			t.Fatalf("常駐メモリを読めなかった PID %d が %.1f MB で載っています。"+
				"消えた直後のプロセスが、常駐 0 の生きたプロセスに見えます", s.pid, *v)
		}
	}
}

// 読めるときは、これまで通り値が載ること。
func TestAReadableProcessIsStillListed(t *testing.T) {
	orig := readVmRSSFn
	readVmRSSFn = func(int) (uint64, memState) { return 1234, memMeasured }
	t.Cleanup(func() { readVmRSSFn = orig })

	stats, _, err := readProcessStatsRaw()
	if err != nil {
		t.Fatalf("readProcessStatsRaw: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("読めているのに1件も返っていません")
	}
	v := memMB(stats[0].memKB, stats[0].mem)
	if v == nil || *v == 0 {
		t.Fatalf("読めた 1234 kB が %v として出ています", v)
	}
}

// 一覧が、この端末の PID をほぼ取りこぼさないこと。
//
// **89% が消えていたのが今回の欠陥です。** 数の一致まで求めると
// 走るたびに揺れるので、桁で留めます。
func TestTheStatsListCoversMostOfProcfs(t *testing.T) {
	procs, err := processListImpl()
	if err != nil {
		t.Fatalf("processListImpl: %v", err)
	}
	stats, _, err := readProcessStatsRaw()
	if err != nil {
		t.Fatalf("readProcessStatsRaw: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("プロセスが1件も見えません")
	}
	if len(stats)*2 < len(procs) {
		t.Fatalf("プロセス一覧 %d 件に対して stats が %d 件しかありません。"+
			"**届いた側には、全部入りの snapshot と欠けた snapshot を"+
			"見分ける手立てがありません**", len(procs), len(stats))
	}
}

// 測れなかったメモリが、JSON に出ないこと。
//
// **フィールドが無いことが「測っていない」の表現です。** 0.0 を出すと、
// 常駐 0 という測定値になります。
func TestUnmeasuredMemoryIsAbsentFromTheWire(t *testing.T) {
	cases := []struct {
		name string
		st   memState
		want bool // mem_mb が出るか
	}{
		{"測れた", memMeasured, true},
		{"ユーザ空間なし", memNoUserSpace, false},
		{"読めない", memUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(ProcessStatEntry{
				PID: 1, Name: "x", CPUPct: 12.5, MemMB: memMB(2048, tc.st),
			})
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			if _, ok := m["mem_mb"]; ok != tc.want {
				t.Errorf("mem_mb の有無 = %v, want %v (%s)", ok, tc.want, b)
			}
			// CPU は常に出ること。**メモリの都合で CPU を落とさないこと。**
			if m["cpu_pct"] != 12.5 {
				t.Errorf("cpu_pct = %v, want 12.5", m["cpu_pct"])
			}
		})
	}
}

// memState の零値が memUnknown であること。
//
// **触り忘れたフィールドが「測った 0」になる向きには倒れないこと。**
// Windows の readOneProcess は成功したときにだけ mem を書きます。
func TestTheZeroMemStateIsUnknown(t *testing.T) {
	var s processStatRaw
	if s.mem != memUnknown {
		t.Fatalf("零値 = %v, want memUnknown", s.mem)
	}
	if memMB(0, s.mem) != nil {
		t.Error("零値のまま mem_mb が出ています")
	}
}

// 既定が本物を指していること。差し替えられる作りにした分、要ります。
func TestTheDefaultVmRSSReaderIsTheRealOne(t *testing.T) {
	if reflect.ValueOf(readVmRSSFn).Pointer() != reflect.ValueOf(readVmRSS).Pointer() {
		t.Error("readVmRSSFn が本物の実装を指していません")
	}
}

// ── 読み取りの分岐（parseVmRSS）─────────────────────────────────────────
//
// **実機の /proc は常に整形された内容を返します。** 壊れた行も途中で
// 切れた status も作れないので、開くところと読むところが同じ関数のうちは
// この4本が書けませんでした。変異が3件生き残って分かりました。

func TestParseVmRSSOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantKB  uint64
		wantSt  memState
	}{
		{
			name:    "普通のプロセス",
			content: "Name:\tbash\nVmRSS:\t  4096 kB\nThreads:\t1\n",
			wantKB:  4096, wantSt: memMeasured,
		},
		{
			// カーネルスレッド。**行が無いのは事実で、失敗ではありません。**
			name:    "VmRSS の行が無い",
			content: "Name:\tkworker/0:1\nState:\tS (sleeping)\nThreads:\t1\n",
			wantKB:  0, wantSt: memNoUserSpace,
		},
		{
			// **数値として読めないものを 0 にしません。** 0 は測定値です。
			name:    "数値として読めない",
			content: "Name:\tbash\nVmRSS:\t   ??? kB\n",
			wantKB:  0, wantSt: memUnknown,
		},
		{
			name:    "値が欠けている",
			content: "Name:\tbash\nVmRSS:\n",
			wantKB:  0, wantSt: memUnknown,
		},
		{
			name:    "空",
			content: "",
			wantKB:  0, wantSt: memNoUserSpace,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kb, st := parseVmRSS(strings.NewReader(tc.content))
			if kb != tc.wantKB || st != tc.wantSt {
				t.Errorf("parseVmRSS = (%d, %v), want (%d, %v)",
					kb, st, tc.wantKB, tc.wantSt)
			}
		})
	}
}

// 途中で読めなくなった status を、カーネルスレッドと取り違えないこと。
//
// **消えたプロセスの status は切れます。** VmRSS 行に届く前に読み取りが
// 失敗すると、行が無いのとまったく同じ姿になります。
func TestATruncatedStatusIsNotAKernelThread(t *testing.T) {
	r := io.MultiReader(
		strings.NewReader("Name:\tbash\nState:\tR\n"),
		&erroringReader{},
	)
	kb, st := parseVmRSS(r)
	if st != memUnknown {
		t.Errorf("parseVmRSS = (%d, %v), want memUnknown。**読み切れなかったのと、"+
			"VmRSS が無いのは別です**", kb, st)
	}
}

type erroringReader struct{}

func (*erroringReader) Read([]byte) (int, error) { return 0, errors.New("読み取り中断") }

// readVmRSS が parseVmRSS を通っていること。
// **切り出した側だけ検査して、本物が別の実装のままにならないこと。**
func TestReadVmRSSGoesThroughTheParser(t *testing.T) {
	kb, st := readVmRSS(os.Getpid())
	f, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // 読み取り専用
	wantKB, wantSt := parseVmRSS(f)
	if st != wantSt || st != memMeasured {
		t.Fatalf("readVmRSS = %v, parseVmRSS = %v", st, wantSt)
	}
	// 常駐メモリは走るあいだに動くので、桁で見ます。
	if kb == 0 || wantKB == 0 {
		t.Fatalf("kB が 0 です (readVmRSS=%d parseVmRSS=%d)", kb, wantKB)
	}
}
