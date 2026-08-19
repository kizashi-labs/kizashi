// build tag を付けていないのは意図です。付けると Linux では対象が
// 1件も見えず、検査は永久に緑になります。

package windows_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// 「調べていない」と「調べたが分からなかった」を、同じ空文字で表さないこと。
//
// `process_etw.go` の `if evt.IntegrityLevel == ""` は「まだ埋めていない、
// 埋めよう」の合図です。`tokenIntegrityLevel` も失敗時に "" を返していたので、
// **2つの状態が1つの値に潰れていました。**
//
// 分けた結果:
//
//	""         トークンを開けなかった（調べるところまで行けていない）
//	"unknown"  開けたが、ラベルを読めなかった
//	"High" 等  読めた
//
// 検知は変わりません（`IntegrityLevel: High` はどちらにも一致しません）。
// **変わるのは、運用者が見分けられることです。**

func TestTokenLookupsSayUnknownNotEmpty(t *testing.T) {
	const path = "integrity_level.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}

	checked := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name != "tokenIntegrityLevel" && fn.Name.Name != "tokenLogonID" {
			continue
		}
		checked++
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return true
			}
			if lit, ok := ret.Results[0].(*ast.BasicLit); ok && lit.Value == `""` {
				t.Errorf("%s が空文字を返しています。**「まだ調べていない」と"+
					"同じ値なので、2つの状態が潰れます**", fn.Name.Name)
			}
			return true
		})
	}
	if checked != 2 {
		t.Errorf("対象の関数が %d 個しか見つかりません（2個のはず）。"+
			"改名したのならこの検査も直してください", checked)
	}
}

// 埋め込み側は、空文字を「まだ埋めていない」として使い続けること。
//
// **こちらを "unknown" に変えると、埋め込みが一度も走らなくなります。**
// 表し方を直すつもりで、調べる処理そのものを止めることになります。
func TestTheFillSignalIsStillTheEmptyString(t *testing.T) {
	src, err := os.ReadFile("process_etw.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, `evt.IntegrityLevel == ""`) {
		t.Error("埋め込みの合図が空文字ではなくなっています。" +
			"調べる処理が走らなくなっていないか確かめてください")
	}
	if strings.Contains(s, `evt.IntegrityLevel == "unknown"`) {
		t.Error(`合図に "unknown" を使っています。**調べて分からなかった` +
			`ものを、もう一度調べ直します**`)
	}
}
