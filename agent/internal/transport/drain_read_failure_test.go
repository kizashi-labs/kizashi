package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// オフラインバッファを「読めなかった」と「もう無い」を、drainBuffer が
// 分けていること。
//
// 以前は1本の条件でした:
//
//	rawBatch, err := c.buffer.ReadBatch(batchSize)
//	if err != nil || len(rawBatch) == 0 {
//	    return
//	}
//
// 読み出しに失敗すると、**バッファが空だったのとまったく同じ扱いで黙って
// 戻ります。** 溜めたイベントはディスクに残ったまま、このドレインでは
// 二度と試されず、ログにも何も出ません。
//
// サーバから見ると、その端末は「切れていて、報告することが何も無かった」
// 姿になります。オフライン中に集めた分が丸ごと出てこないことと、本当に
// 何も起きなかったことの区別がつきません。**エージェントの仕事は、
// 繋がっていない間の出来事を後から届けることです。**
//
// 実際に動かして確かめられれば、そちらのほうが良い検査です。ReadBatch は
// *RingBuffer の具象メソッドで、GRPCClient は interface を挟んでいないため、
// 失敗する buffer を差し込めません。差し込めるようにする改修は transport の
// 構造に触るので、ここでは形を固定するに留めます。**形の検査であることを
// 隠さないために書いておきます。**

func TestDrainSeparatesAReadFailureFromAnEmptyBuffer(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "grpc_client.go", nil, 0)
	if err != nil {
		t.Fatalf("grpc_client.go を読めません: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "drainBuffer" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("drainBuffer が見つかりません")
	}

	// ReadBatch の呼び出しの直後に、err だけを見る if があること。
	var readBatchAt token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ReadBatch" {
			readBatchAt = call.Pos()
		}
		return true
	})
	if !readBatchAt.IsValid() {
		t.Fatal("drainBuffer が ReadBatch を呼んでいません。" +
			"この検査は対象を見失っています")
	}

	var errOnly, lenOnly, merged bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok || is.Pos() < readBatchAt {
			return true
		}
		cond := condText(fset, is.Cond)
		hasErr := strings.Contains(cond, "err != nil")
		hasLen := strings.Contains(cond, "len(rawBatch) == 0")
		switch {
		case hasErr && hasLen:
			merged = true
		case hasErr && !hasLen:
			errOnly = true
		case hasLen && !hasErr:
			lenOnly = true
		}
		return true
	})

	if merged {
		t.Error("drainBuffer が「読めなかった」と「もう無い」を1つの条件に" +
			"まとめています。読み出しに失敗した回が、空だった回と同じ扱いで" +
			"黙って戻ります")
	}
	if !errOnly {
		t.Error("ReadBatch の失敗だけを見る分岐がありません。" +
			"失敗が誰にも届かないまま、溜めたイベントが残ります")
	}
	if !lenOnly {
		t.Error("空だったことだけを見る分岐がありません")
	}
}

func condText(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	var walk func(ast.Expr)
	walk = func(x ast.Expr) {
		switch v := x.(type) {
		case *ast.BinaryExpr:
			walk(v.X)
			sb.WriteString(" " + v.Op.String() + " ")
			walk(v.Y)
		case *ast.Ident:
			sb.WriteString(v.Name)
		case *ast.CallExpr:
			walk(v.Fun)
			sb.WriteString("(")
			for i, a := range v.Args {
				if i > 0 {
					sb.WriteString(", ")
				}
				walk(a)
			}
			sb.WriteString(")")
		case *ast.SelectorExpr:
			walk(v.X)
			sb.WriteString("." + v.Sel.Name)
		case *ast.BasicLit:
			sb.WriteString(v.Value)
		case *ast.ParenExpr:
			walk(v.X)
		}
	}
	walk(e)
	return sb.String()
}

// 判定そのものが動くこと。木がきれいなあいだ、上の3つの t.Error は
// どれも通りません。
func TestTheDrainRuleReadsConditions(t *testing.T) {
	fset := token.NewFileSet()
	for _, c := range []struct{ src, want string }{
		{"err != nil || len(rawBatch) == 0", "err != nil || len(rawBatch) == 0"},
		{"err != nil", "err != nil"},
		{"len(rawBatch) == 0", "len(rawBatch) == 0"},
	} {
		e, perr := parser.ParseExpr(c.src)
		if perr != nil {
			t.Fatalf("parse %s: %v", c.src, perr)
		}
		if got := condText(fset, e); got != c.want {
			t.Errorf("condText(%q) = %q, want %q", c.src, got, c.want)
		}
	}
}
