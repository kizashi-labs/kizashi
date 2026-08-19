package collector

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/edr-platform/agent/internal/hostmetrics"
)

// 測れなかった値が、測定値として送られないこと。
//
// 0 は測定値として最も強い主張になります:
//
//	CPU 0%       → 「アイドル」。高負荷を探す側からは**問題なし**
//	ディスク 0GB → 「空きが全く無い」。**いちばん深刻な観測値**
//
// どちらも、測っていないことを画面上の断定に化けさせます。しかも向きが
// 逆なので、「安全側に倒す」という一言では片付きません。
//
// 実測でこうなっていました:
//
//	Windows  readCPUStat・readDiskFreeGB とも未実装 → CPU 0% / ディスク 0GB
//	macOS    readCPUStat 未実装                     → CPU 0%
//	Linux    Statfs 失敗時                          → ディスク 0GB
//
// いまは欄ごと落とします。`omitempty` + ポインタなので、JSON に出ません。

func TestAnUnmeasuredSnapshotOmitsItsFields(t *testing.T) {
	// **3つとも未設定で始めます。** 以前はメモリだけ値を入れていたので、
	// メモリの omitempty を外す変異が生き残りました —— 落とす仕組みを
	// 確かめる検査が、その欄だけ埋めていました。
	b, err := json.Marshal(resourceSnapshot{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)

	if strings.Contains(got, "mem_mb") {
		t.Errorf("測っていないメモリが載っています: %s\n"+
			"0 MB は「使っていない」という測定値です", got)
	}
	if strings.Contains(got, "cpu_pct") {
		t.Errorf("測っていない CPU が載っています: %s\n"+
			"0%% は「アイドル」という測定値です", got)
	}
	if strings.Contains(got, "disk_free_gb") {
		t.Errorf("測っていないディスクが載っています: %s\n"+
			"0 GB は「満杯」という測定値です", got)
	}
	// 測った値は載ること。**落とす側だけ直して、測れた分まで消さないこと。**
	mem := 12.5
	b2, err := json.Marshal(resourceSnapshot{MemMB: &mem})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b2), `"mem_mb":12.5`) {
		t.Errorf("測っている値まで落ちています: %s", b2)
	}
}

// 測れた値は、0 でも載ること。
//
// **本当に 0% のときに落とすと、今度は逆向きの嘘になります。**
// omitempty は値の 0 で落とすので、ポインタでなければこれは通りません。
func TestAMeasuredZeroIsStillReported(t *testing.T) {
	zero := 0.0
	b, err := json.Marshal(resourceSnapshot{CPUPercent: &zero, DiskFreeGB: &zero})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)

	if !strings.Contains(got, `"cpu_pct":0`) {
		t.Errorf("測った 0%% が落ちています: %s", got)
	}
	if !strings.Contains(got, `"disk_free_gb":0`) {
		t.Errorf("測った 0 GB が落ちています: %s", got)
	}
}

// 測定関数を差し替えて確かめます。
//
// **実機で成功してしまうと、失敗の分岐を一度も通れません。** 変異検査で
// 実際に露見しました —— 「測れたかを見ずに値を載せる」ように壊しても、
// Linux では Statfs が成功するので何も変わりませんでした。
func withReaders(t *testing.T, disk func() (float64, bool), cpu func() (uint64, uint64)) {
	t.Helper()
	od, oc := readDiskFreeGBFn, readCPUStatFn
	if disk != nil {
		readDiskFreeGBFn = disk
	}
	if cpu != nil {
		readCPUStatFn = cpu
	}
	t.Cleanup(func() { readDiskFreeGBFn, readCPUStatFn = od, oc })
}

func withMemory(t *testing.T, mem func() (float64, float64, bool)) {
	t.Helper()
	orig := hostMemoryFn
	hostMemoryFn = mem
	t.Cleanup(func() { hostMemoryFn = orig })
}

// 端末のメモリを測れなかったときに、載せないこと。
//
// **以前はエージェント自身の Go ランタイムの使用量を載せていました。**
// 常に値が出るので「測れている」ように見えますが、端末のメモリ使用量とは
// 別物です。測れていないのではなく、別のものを測っていました。
func TestAnUnmeasurableMemoryIsNotReported(t *testing.T) {
	withMemory(t, func() (float64, float64, bool) { return 0, 0, false })

	if snap := (&ResourceCollector{}).collect(0, 0); snap.MemMB != nil {
		t.Errorf("測れなかったのに %v MB を載せています", *snap.MemMB)
	}
}

// 測れたら、端末の使用量を載せること。
func TestAMeasurableMemoryIsReported(t *testing.T) {
	withMemory(t, func() (float64, float64, bool) { return 2048, 8192, true })

	snap := (&ResourceCollector{}).collect(0, 0)
	if snap.MemMB == nil {
		t.Fatal("測れているのにメモリが落ちています")
	}
	if *snap.MemMB != 2048 {
		t.Errorf("mem = %v, want 2048", *snap.MemMB)
	}
}

// 測れなかったディスクを載せないこと。
//
// **戻り値の bool を無視すると、0 GB ＝「満杯の端末」が送られます。**
// Windows は未実装なので常にこの経路で、実装していないことが
// いちばん深刻な観測値に化けていました。
func TestAnUnmeasurableDiskIsNotReportedAsZero(t *testing.T) {
	withReaders(t, func() (float64, bool) { return 0, false }, nil)

	if snap := (&ResourceCollector{}).collect(0, 0); snap.DiskFreeGB != nil {
		t.Errorf("測れなかったのに %v GB を載せています。"+
			"0 GB は「空きが全く無い」という測定値です", *snap.DiskFreeGB)
	}
}

// 測れたディスクは、0 でも載せること。
func TestAMeasurableDiskIsReportedEvenWhenZero(t *testing.T) {
	withReaders(t, func() (float64, bool) { return 0, true }, nil)

	snap := (&ResourceCollector{}).collect(0, 0)
	if snap.DiskFreeGB == nil {
		t.Fatal("測った 0 GB が落ちています。本当に満杯の端末が見えません")
	}
	if *snap.DiskFreeGB != 0 {
		t.Errorf("disk = %v, want 0", *snap.DiskFreeGB)
	}
}

// 差が取れないときに、CPU を 0% として載せないこと。
//
// prevTotal が 0（初回）、カウンタが進んでいない、巻き戻った ——
// どれも「まだ分からない」であって、アイドルではありません。
func TestCollectWithoutADeltaOmitsCPU(t *testing.T) {
	// 初回（prev が 0）
	withReaders(t, nil, func() (uint64, uint64) { return 100, 1000 })
	if snap := (&ResourceCollector{}).collect(0, 0); snap.CPUPercent != nil {
		t.Errorf("差が取れないのに CPU %v%% を載せています", *snap.CPUPercent)
	}

	// カウンタが進んでいない
	if snap := (&ResourceCollector{}).collect(100, 1000); snap.CPUPercent != nil {
		t.Errorf("差が無いのに CPU %v%% を載せています", *snap.CPUPercent)
	}

	// 巻き戻り（いまの total が前より小さい）
	if snap := (&ResourceCollector{}).collect(200, 2000); snap.CPUPercent != nil {
		t.Errorf("巻き戻ったのに CPU %v%% を載せています", *snap.CPUPercent)
	}
}

// idle の伸びが total の伸びを超えたら、CPU% を出さないこと。
//
// **出すと負の使用率になり、uint の引き算なので巨大な正の数に化けます。**
// カウンタが別々に巻き戻ると起きます。
func TestImpossibleIdleGrowthOmitsCPU(t *testing.T) {
	withReaders(t, nil, func() (uint64, uint64) { return 900, 1100 })

	// prevIdle=100, prevTotal=1000 → deltaIdle=800, deltaTotal=100
	if snap := (&ResourceCollector{}).collect(100, 1000); snap.CPUPercent != nil {
		t.Errorf("あり得ない差なのに CPU %v%% を載せています", *snap.CPUPercent)
	}
}

// 差が取れれば、CPU% を載せること。塞ぐ側だけ直して、測れる場合まで
// 落としていないこと。
func TestAProperDeltaIsReported(t *testing.T) {
	withReaders(t, nil, func() (uint64, uint64) { return 150, 1200 })

	snap := (&ResourceCollector{}).collect(100, 1000) // idle +50 / total +200
	if snap.CPUPercent == nil {
		t.Fatal("測れているのに CPU が落ちています")
	}
	if *snap.CPUPercent < 74.9 || *snap.CPUPercent > 75.1 {
		t.Errorf("cpu = %v, want 75", *snap.CPUPercent)
	}
}

// 各プラットフォームの実装が、測れたかを返す形になっていること。
//
// **Linux では windows/darwin のファイルがコンパイルされません。**
// 変異検査で `resource_collector_windows.go` を壊しても何も落ちませんでした
// —— ビルドされないので当然です。ここはソースを文字として読みます。
// 走らせる OS に関係なく、3つとも見ます。
func TestEveryPlatformReportsWhetherItMeasured(t *testing.T) {
	// **3つとも実装済みになりました。** Windows は "not implemented
	// without cgo" と書かれたまま常に (0, false) を返していて、
	// **ディスク空き容量を一度も報告していませんでした** —— cgo は要らず、
	// GetDiskFreeSpaceEx は x/sys/windows にあります。
	for _, file := range []string{
		"resource_collector_linux.go",
		"resource_collector_darwin.go",
		"resource_collector_windows.go",
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s を読めません: %v", file, err)
			continue
		}
		src := string(b)

		if !strings.Contains(src, "func readDiskFreeGB() (float64, bool)") {
			t.Errorf("%s: readDiskFreeGB が「測れたか」を返しません。"+
				"float64 だけだと、0 GB が「満杯」という測定値になります", file)
		}
		// 失敗の分岐が「測れた」を返していないこと。
		// **0 GB は「満杯の端末」という測定値です。**
		if strings.Contains(src, "return 0, true") {
			t.Errorf("%s: 測れなかった分岐が「測れた 0 GB」を返しています。"+
				"**実装していないこと・測れなかったことが、いちばん深刻な"+
				"観測値に化けます**", file)
		}
		// 実装が本当に入っていること。**「測れない」と書いてあるだけの
		// ファイルに戻ったら、この端末は永久に報告しません。**
		if strings.Contains(src, "func readDiskFreeGB() (float64, bool) {\n\treturn 0, false\n}") {
			t.Errorf("%s: readDiskFreeGB が空実装に戻っています", file)
		}
	}
}

// Windows の資源測定が、実装に置き換わっていること。
//
// **Linux では windows のファイルがコンパイルされません。** ソースを
// 文字として読みます。
func TestWindowsResourceReadersAreImplemented(t *testing.T) {
	b, err := os.ReadFile("resource_collector_windows.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	// **コメントではなくコードを見ます。** 文字列として探すと、
	// 実装を消しても doc コメントに名前が残っていて通ります ——
	// 変異が2件それで生き残りました。
	f, err := parser.ParseFile(token.NewFileSet(), "resource_collector_windows.go", b, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}
	code := map[string]bool{}
	strs := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			code[v.Sel.Name] = true
		case *ast.Ident:
			code[v.Name] = true
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				strs[strings.Trim(v.Value, `"`)] = true
			}
		}
		return true
	})

	for _, want := range []string{
		"GetDiskFreeSpaceEx", // cgo は要りません
		"SystemCPUCounters",  // CPU の読み取りは1本化しました
	} {
		if !code[want] {
			t.Errorf("resource_collector_windows.go が %s を呼んでいません。"+
				"**この端末は CPU もディスクも一度も報告しません**", want)
		}
	}
	// **`C:\\` の決め打ちに戻っていないこと。** SystemDrive が D: の
	// 端末では、別のボリュームの空きを端末の空き容量として報告します。
	if !strs["SystemDrive"] {
		t.Error("システムドライブを決め打ちしています。SystemDrive が D: の" +
			"端末では、別のボリュームの空きを報告します")
	}
}

// 差し替え可能にした既定が、本物を指していること。
//
// **これが無いと、既定をスタブにする変異が生き残ります。** 実際に
// 生き残りました —— どの検査も自分で差し替えるので、既定が何であっても
// 通ります。差し替えられる作りにした分、既定を留める1本が要ります。
func TestTheDefaultReadersArePlatformImplementations(t *testing.T) {
	if reflect.ValueOf(readDiskFreeGBFn).Pointer() !=
		reflect.ValueOf(readDiskFreeGB).Pointer() {
		t.Error("readDiskFreeGBFn が本物の実装を指していません")
	}
	if reflect.ValueOf(readCPUStatFn).Pointer() !=
		reflect.ValueOf(readCPUStat).Pointer() {
		t.Error("readCPUStatFn が本物の実装を指していません")
	}
	if reflect.ValueOf(hostMemoryFn).Pointer() !=
		reflect.ValueOf(hostmetrics.Memory).Pointer() {
		t.Error("hostMemoryFn が本物の実装を指していません")
	}
}
