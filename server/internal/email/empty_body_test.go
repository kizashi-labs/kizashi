package email

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// 本文が空のメールを送らないこと。
//
// renderTemplate は解析に失敗すると "" を返し、Execute の失敗も捨てて
// いました。呼び出し側 (SendInvitation / SendPasswordReset /
// SendEmailVerification / SendAlertNotification) はその "" をそのまま
// Send に渡します。パスワード再設定の案内が白紙で届く、という形です。
//
// テンプレート自体はコード内の定数なので、実運用で解析に失敗するのは
// 誰かがテンプレートを編集したときです。つまり気づくのはメールを
// 受け取った人だけ、ということになります。
//
// 上の関数の中身はテストから直接動かせるので、ここでは呼び出し側が
// 戻り値のエラーを確かめていることを留めます。

func TestEverySendCheckedItsRender(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sender.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	checked := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		body := render(fset, fn.Body)
		if !strings.Contains(body, "renderTemplate") {
			continue
		}
		if fn.Name.Name == "renderTemplate" || fn.Name.Name == "renderTemplateDynamic" {
			continue
		}
		checked++
		if !strings.Contains(body, "if err != nil") {
			t.Errorf("%s: 本文の組み立て結果を確かめずに送信しています。"+
				"テンプレートが壊れていると、本文が空のまま届きます", fn.Name.Name)
		}
	}
	if checked == 0 {
		t.Fatal("renderTemplate を使う送信関数が1つも見つかりません。走査が届いていません")
	}
}

func render(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return ""
	}
	return sb.String()
}
