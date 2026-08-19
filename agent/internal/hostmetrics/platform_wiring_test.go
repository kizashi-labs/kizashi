package hostmetrics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// build tag を付けていないのは意図です。**付けると、Linux の CI では
// Windows と macOS のファイルが1件も見えず、検査は永久に緑になります。**
// （`internal/platform/windows/sedebug_contract_test.go` と同じ形です。）
//
// 走らせられないコードについて、走らせずに確かめられることは2つです:
//
//  1. 算術と解析が、検査の通っている関数を**通っていること**
//  2. 実装のないプラットフォームが、**0 を測定値として返さないこと**
//
// 1 が要るのは、算術を切り出しただけでは何も保証されないからです。
// **切り出した側だけ検査して、本物が別の実装のままなら、検査は緑で値は
// 嘘です。** このキャンペーンで `readVmRSS` と `scanPidMapsStats` の
// ときに同じ穴を開けかけました。

func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s を解析できません: %v", path, err)
	}
	return f
}

// funcCalls returns the names of functions called inside the named top-level
// function.
func funcCalls(t *testing.T, f *ast.File, name string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == name && d.Recv == nil {
			fn = d
		}
	}
	if fn == nil {
		t.Fatalf("%s が見つかりません。改名したのならこの検査も直してください", name)
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			out[fun.Name] = true
		case *ast.SelectorExpr:
			out[fun.Sel.Name] = true
		}
		return true
	})
	return out
}

// Windows の読み取りが、検査の通っている算術を通っていること。
func TestWindowsReadersUseTheTestedArithmetic(t *testing.T) {
	f := parseGoFile(t, "cpu_windows.go")

	cpu := funcCalls(t, f, "readCPUStat")
	for _, want := range []string{"windowsCPUTotals", "ftTicks"} {
		if !cpu[want] {
			t.Errorf("readCPUStat が %s を呼んでいません。**切り出した算術を"+
				"通らないと、検査は緑のままで値だけが嘘になります**", want)
		}
	}
	// FILETIME を絶対時刻として扱う罠。**このリポジトリで実際に踏み、
	// 全プロセスの CPU 時間が 0 になっていました。**
	if cpu["Nanoseconds"] {
		t.Error("Filetime.Nanoseconds() を使っています。あれは FILETIME を" +
			"1601 起点の絶対時刻として扱い、Unix エポック分を引きます —— " +
			"GetSystemTimes が返すのは経過時間です")
	}

	mem := funcCalls(t, f, "readMemory")
	if !mem["windowsMemoryMB"] {
		t.Error("readMemory が windowsMemoryMB を呼んでいません")
	}
}

// macOS の読み取りが、検査の通っている組み立てを通っていること。
func TestDarwinReadersUseTheTestedArithmetic(t *testing.T) {
	f := parseGoFile(t, "cpu_darwin.go")
	mem := funcCalls(t, f, "readMemory")
	if !mem["darwinMemoryFrom"] {
		t.Error("readMemory が darwinMemoryFrom を呼んでいません")
	}
	// **コマンドを直に起動していないこと。** 差し替えられないと、
	// 失敗の分岐を検査から通せません。
	if mem["Command"] || mem["CommandContext"] {
		t.Error("readMemory が exec を直に呼んでいます。" +
			"vmStatFn / memSizeFn を通してください")
	}
}

// 実装のないプラットフォームが、0 を測定値として返さないこと。
//
// **`return 0, 0, true` が1つあれば、そのプラットフォームの全端末が
// 恒久的に「CPU 0%」「メモリ 0MB」を報告します。** それはこの
// パッケージが存在する理由そのものです。
func TestTheUnimplementedStubNeverClaimsAMeasurement(t *testing.T) {
	f := parseGoFile(t, "cpu_other.go")
	for _, name := range []string{"readCPUStat", "readMemory"} {
		var fn *ast.FuncDecl
		for _, d := range f.Decls {
			if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == name {
				fn = d
			}
		}
		if fn == nil {
			t.Fatalf("%s が見つかりません", name)
		}
		var returns int
		ast.Inspect(fn, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			returns++
			last := ret.Results[len(ret.Results)-1]
			id, ok := last.(*ast.Ident)
			if !ok || id.Name != "false" {
				t.Errorf("%s の return が測れたことにしています: %v", name, last)
			}
			return true
		})
		if returns == 0 {
			t.Errorf("%s に return がありません", name)
		}
	}
}

// 実装したプラットフォームが、stub の build tag から外れていること。
//
// **外し忘れると redeclared でビルドが落ちる**ので実害は出ませんが、
// tag が広いままだと「まだ実装していない」と読めます。
func TestTheStubBuildTagMatchesWhatIsImplemented(t *testing.T) {
	src, err := os.ReadFile("cpu_other.go")
	if err != nil {
		t.Fatal(err)
	}
	head := string(src)
	if i := strings.Index(head, "\npackage "); i > 0 {
		head = head[:i]
	}
	for _, implemented := range []string{"linux", "windows", "darwin"} {
		if !strings.Contains(head, "!"+implemented) {
			t.Errorf("cpu_other.go の build tag が %s を除いていません。"+
				"実装済みです: %q", implemented, strings.TrimSpace(head))
		}
	}
}

// 実装したファイルが実在すること。
//
// **上の検査は、ファイルが消えても「解析できません」で落ちます。**
// ここは「実装したと言っている面が実在する」ことを別に言います。
func TestTheImplementedPlatformFilesExist(t *testing.T) {
	for _, p := range []string{"cpu_linux.go", "cpu_windows.go", "cpu_darwin.go"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s がありません: %v", p, err)
		}
	}
}
