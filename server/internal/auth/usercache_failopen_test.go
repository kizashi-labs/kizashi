package auth

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// 「利用者がもう居ない」と「利用者の状態を確認できない」。
//
// IsActive は以前こう書かれていました:
//
//	if err != nil {
//	    // Unknown user or DB error: allow through to avoid false lockouts.
//	    return true
//	}
//
// 2つを1つの答えにしています。データベース障害のあいだ全員を締め出さない
// という判断そのものは筋が通っています。ただし削除済みの利用者のトークンも
// 同じ道を通り、期限切れまで有効なままになります。そして通したことは
// どこにも残りません。
//
// 分けました。行が無い（利用者が居ない）なら通しません。DB 障害なら通し、
// 通したことを記録します。fail-open は残しますが、見えない fail-open は
// やめます。
//
// 実際に落ちる経路にはデータベースが要るので、ここは形を留めます。

func TestIsActiveSeparatesAbsenceFromFailure(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "usercache.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == "IsActive" {
			fn = x
		}
	}
	if fn == nil {
		t.Fatal("IsActive が見つかりません。走査が届いていません")
	}

	var absenceDenies, failureLogsAndAllows bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		cond, body := render(fset, is.Cond), render(fset, is.Body)
		switch {
		case strings.Contains(cond, "pgx.ErrNoRows"):
			if strings.Contains(body, "return false") {
				absenceDenies = true
			}
		case strings.Contains(cond, "err != nil"):
			if strings.Contains(body, "return true") && strings.Contains(body, "slog.") {
				failureLogsAndAllows = true
			}
		}
		return true
	})

	if !absenceDenies {
		t.Error("存在しない利用者のトークンを通しています。" +
			"削除した利用者が、トークンの期限まで動けます")
	}
	if !failureLogsAndAllows {
		t.Error("DB 障害のときに黙って通しています。fail-open を選ぶのは構いませんが、" +
			"無効化したはずの利用者が通っている時間帯が、どこにも残りません")
	}
}

func render(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return ""
	}
	return sb.String()
}
