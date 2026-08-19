package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// コメント本文の規則。
//
// **この規則は、検査の側にだけありました。** `internal/store` の
// `incident_comments_pure_test.go` に `isValidCommentBody`（空白のみは
// 無効、10,000 文字超は無効）というヘルパーが置いてあり、そのヘルパー
// 自身が試されていました。**製品にその規則はありません。**
// `binding:"required"` は空文字列しか弾かないので、空白だけの本文も、
// 100万文字の本文も、そのまま TEXT カラムに入っていました。
//
// 規則の方を足したので、ここで留めます。

func TestValidateCommentBodyRejectsWhitespaceOnly(t *testing.T) {
	for _, body := range []string{"", " ", "\t\n", "   \r\n  "} {
		if msg := validateCommentBody(body); msg == "" {
			t.Errorf("%q を受け入れています。**binding:\"required\" は"+
				"空文字列しか弾きません**", body)
		}
	}
}

func TestValidateCommentBodyAcceptsOrdinaryText(t *testing.T) {
	for _, body := range []string{
		"確認しました",
		"a",
		strings.Repeat("あ", maxCommentBodyLength),
	} {
		if msg := validateCommentBody(body); msg != "" {
			t.Errorf("%d 文字の本文を拒否しています: %s",
				len([]rune(body)), msg)
		}
	}
}

func TestValidateCommentBodyCapsLength(t *testing.T) {
	if msg := validateCommentBody(strings.Repeat("a", maxCommentBodyLength+1)); msg == "" {
		t.Error("上限を超えた本文を受け入れています。" +
			"**カラムは TEXT で、上限が無いとそのまま入ります**")
	}
}

// 長さをルーン数で数えること。
//
// **バイト数で数えると、日本語のコメントが3分の1の長さで弾かれます。**
func TestCommentLengthCountsRunesNotBytes(t *testing.T) {
	// 上限ちょうどの日本語（UTF-8 で 3 倍のバイト数）。
	body := strings.Repeat("あ", maxCommentBodyLength)
	if len(body) <= maxCommentBodyLength {
		t.Fatal("この検査の前提が崩れています（バイト数が上限を超えていません）")
	}
	if msg := validateCommentBody(body); msg != "" {
		t.Errorf("上限ちょうどの日本語を拒否しています: %s。"+
			"**バイト数で数えています**", msg)
	}
}

// Add が、この検証を通っていること。
//
// **規則を書いただけでは何も変わりません。** 呼ばれていなければ、
// 空白だけのコメントも 100 万文字のコメントも、これまで通り入ります。
// gin の HTTP 経路を組み立てずに済むよう、呼んでいることを AST で見ます。
func TestAddCallsTheBodyValidator(t *testing.T) {
	const path = "incident_comments_handler.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}

	var add *ast.FuncDecl
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Add" && fn.Recv != nil {
			add = fn
		}
	}
	if add == nil {
		t.Fatal("Add が見つかりません。改名したのならこの検査も直してください")
	}

	called := false
	ast.Inspect(add, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "validateCommentBody" {
			called = true
		}
		return true
	})
	if !called {
		t.Error("Add が validateCommentBody を呼んでいません。" +
			"**規則を書いても、呼ばれていなければ何も変わりません**")
	}
}
