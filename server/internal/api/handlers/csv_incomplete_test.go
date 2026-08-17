package handlers

import (
	"bytes"
	"encoding/csv"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// 流しながら書く CSV に、途中で切れた印が残ること。
//
// **この2つ（`ExportAlerts` / `ExportCompliance`）は 500 に切り替えられ
// ません。** 失敗した時点で、200 もヘッダも最初の行も相手に渡っています。
// できるのはファイル自身に書くことだけです。
//
// **何も書かないと、途中までの CSV が全件として保存されます。**

func TestMarkCSVIncompleteWritesSomethingUnmistakable(t *testing.T) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "title"})
	_ = w.Write([]string{"1", "alert"})
	markCSVIncomplete(w, errors.New("canceling statement due to statement timeout"))
	w.Flush()

	out := buf.String()
	if !strings.Contains(out, "#INCOMPLETE") {
		t.Errorf("印が出ていません。**途中までの CSV が全件として保存されます**\n%s", out)
	}
	// **理由も残すこと。** 印だけだと、なぜ切れたのかを後から追えません。
	if !strings.Contains(out, "statement timeout") {
		t.Errorf("失敗の理由が残っていません\n%s", out)
	}
	// 印が最後にあること —— データ行に紛れると読み飛ばされます。
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "#INCOMPLETE") {
		t.Errorf("印が最終行にありません\n%s", out)
	}
	// 元の行が消えていないこと。
	if !strings.Contains(out, "alert") {
		t.Errorf("読めていた行まで消えています\n%s", out)
	}
}

// 流している書き出しが、その印を実際に書くこと。
//
// **判定を切り出しただけでは足りません。** 呼ぶのをやめれば元に戻り、
// この package の他のどの検査も落ちませんでした（変異が生き残りました）。
func TestStreamingCSVExportsCallTheIncompleteMarker(t *testing.T) {
	const file = "report_export_handler.go"
	want := []string{"ExportAlerts", "ExportCompliance"}

	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("%s を解析できません: %v", file, err)
	}
	for _, name := range want {
		found, calls := false, false
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "markCSVIncomplete" {
						calls = true
					}
				}
				return true
			})
		}
		if !found {
			t.Errorf("%s に %s が見つかりません", file, name)
			continue
		}
		if !calls {
			t.Errorf("%s の %s が `markCSVIncomplete` を呼んでいません。"+
				"**途中で切れた CSV が、全件として手元に残ります**", file, name)
		}
	}
}
