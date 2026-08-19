// build tag を付けていないのは意図です。付けると Linux の CI では
// このファイルの対象が1件も見えず、検査は永久に緑になります。

package windows_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// SeDebugPrivilege を取れなかったことが、黙って捨てられていないこと。
//
// 4つの失敗経路（トークンを開く / 特権名の変換 / LookupPrivilegeValue /
// AdjustTokenPrivileges）はどれも `slog.Warn` を1行書いて `return` して
// いました。**サーバからは、特権のある端末と区別がつきません。**
//
// 何が失われるか: 他ユーザーのプロセスのコマンドラインです。
// **command_line は検知がいちばん寄りかかっている欄で** —— LOLBin、
// 難読化 PowerShell、親子関係の規則はほぼ全部これを見ます ——
// 特権の無い端末では「コマンドライン空のプロセス起動」として上がります。
//
// いまは telemetry に ModePoll で登録します。**ModeFailed ではありません**
// —— センサーは動いていて、劣った手段で集めています。

func TestEveryPrivilegeFailurePathReports(t *testing.T) {
	const path = "process_collector.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "EnableSeDebugPrivilege" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("EnableSeDebugPrivilege が見つかりません。" +
			"改名したのならこの検査も直してください")
	}

	// 失敗して bare return する分岐を数え、全部が報告を通っていること。
	bare, reporting := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Body == nil {
			return true
		}
		hasBareReturn := false
		for _, st := range ifs.Body.List {
			if ret, ok := st.(*ast.ReturnStmt); ok && len(ret.Results) == 0 {
				hasBareReturn = true
			}
		}
		if !hasBareReturn {
			return true
		}
		bare++
		ast.Inspect(ifs.Body, func(x ast.Node) bool {
			if call, ok := x.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "seDebugUnavailable" {
					reporting++
				}
			}
			return true
		})
		return true
	})

	if bare != 4 {
		t.Errorf("失敗経路が %d 本です（4本のはず）。"+
			"走査が届いていないか、経路が変わりました", bare)
	}
	if reporting != bare {
		t.Errorf("%d 本のうち %d 本しか報告していません。"+
			"報告しない経路は、特権のある端末と区別がつきません", bare, reporting)
	}
}

// 報告が ModePoll であること。
//
// **ModeFailed にすると、動いているセンサーが止まっているように見えます。**
// 逆に ModeOff にすると、Aggregate が「設定の選択」として無視するので、
// 報告した気になるだけになります。
func TestTheDegradationIsPollNotFailedOrOff(t *testing.T) {
	src, err := os.ReadFile("process_collector.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "telemetry.ModePoll") {
		t.Error("ModePoll で登録していません")
	}
	if strings.Contains(s, "telemetry.ModeOff") {
		t.Error("ModeOff で登録しています。Aggregate に無視されるので、" +
			"報告した気になるだけです")
	}
	if strings.Contains(s, "telemetry.ModeFailed") {
		t.Error("ModeFailed で登録しています。センサーは動いているので、" +
			"止まっているように見せてしまいます")
	}
}
