package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// **手動にした重要度を、自動計算に戻せること。**
//
// 手動が効くようになるまで、解除は要りませんでした —— `GetScore` が
// 毎回計算し直して同じ行を上書きしていたので、**放っておけば戻って
// いました。** それは解除ではなく、機能していなかっただけです。
//
// 印を見るようにした結果、**一度手で決めた端末は、手で決め直す以外に
// 自動へ戻す方法がなくなりました。** `DELETE /endpoints/:id/criticality`
// がその経路です。
//
// ここの検査は DB を立てずに通ります。**行が消えたあとに何が起きるかは
// `manualCriticality` が決めている**ので、消す側については「正しい行を
// 狙っていること」と「消したあと計算し直して答えること」を見ます。
// 実際に DB を通す往復は `criticality_clear_integration_test.go` です。

const criticalityHandlerFile = "asset_criticality_handler.go"

func parseCriticalityHandler(t *testing.T) *ast.File {
	t.Helper()
	src, err := os.ReadFile(criticalityHandlerFile)
	if err != nil {
		t.Fatalf("%s を読めません: %v", criticalityHandlerFile, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), criticalityHandlerFile, src, 0)
	if err != nil {
		t.Fatalf("%s を解析できません: %v", criticalityHandlerFile, err)
	}
	return f
}

// **解除が、保存と同じ行を狙っていること。**
//
// 鍵の綴りが2つに分かれると、解除は 200 を返して**何も消しません** ——
// 画面は「自動に戻しました」と出し、次に一覧を開くと手動の点数が
// そのまま並びます。`criticalityKey` を通していれば、綴りは1つです。
func TestClearingAManualScoreTargetsTheRowThatSetWrote(t *testing.T) {
	f := parseCriticalityHandler(t)

	if !calls(f, "ClearManualScore", "criticalityKey") {
		t.Error("`ClearManualScore` が `criticalityKey` を通っていません。" +
			"**鍵の綴りが2つに分かれると、解除は 200 を返して何も消しません**")
	}
	if !calls(f, "SetManualScore", "criticalityKey") {
		t.Error("`SetManualScore` が `criticalityKey` を通っていません")
	}

	// 消したあとに計算し直して答えること。**答えを返さないと、画面は
	// 戻った先の点数を知りません**（再取得までのあいだ、手動の点数が
	// 残ります）。
	if !calls(f, "ClearManualScore", "computeScoreForAgent") {
		t.Error("`ClearManualScore` が計算し直していません。" +
			"**解除したのに、答えは手動のままの点数になります**")
	}
}

// **解除が、消すこと以外をしていないこと。**
//
// 「自動に戻った」を別の行として書くと、その行にも読み手が要ります ——
// 読み手が無い行を書いていたのが、この handler の元の欠陥でした。
// `system_metadata` に書くのは `SetManualScore` だけ、という規則は
// `criticality_override_test.go` が留めています。ここでは、解除が
// DELETE であることを見ます。
func TestClearingAManualScoreDeletesTheRow(t *testing.T) {
	f := parseCriticalityHandler(t)

	if got := deletesSystemMetadata(f); len(got) != 1 || got[0] != "ClearManualScore" {
		t.Errorf("`system_metadata` から消している関数 = %v, want [ClearManualScore]。"+
			"**消す代わりに書いて「自動」と印を付けると、その行にも読み手が"+
			"要ります** —— 読み手の無い行が、この handler の元の欠陥でした", got)
	}
}

// deletesFromSystemMetadata — 消し込みの形。
var deletesFromSystemMetadata = regexp.MustCompile(`DELETE\s+FROM\s+SYSTEM_METADATA`)

// deletesSystemMetadata — その file の中で `system_metadata` から
// DELETE している関数名。
//
// **判定を切り出してあるのは、通る木では違反が 0 件だからです。**
// 見本を食わせないと、走査を潰す変異が生き残ります。
func deletesSystemMetadata(f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if deletesFromSystemMetadata.MatchString(strings.ToUpper(lit.Value)) {
				found = true
			}
			return true
		})
		if found {
			out = append(out, fn.Name.Name)
		}
	}
	return out
}

// 走査が効くこと。**違反する見本を食わせて確かめます。**
func TestTheSystemMetadataDeleteScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+src, 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f
	}

	got := deletesSystemMetadata(parse("func d() {\n" +
		"_, _ = p.Exec(ctx, `DELETE FROM system_metadata WHERE key = $1`)\n}"))
	if len(got) != 1 || got[0] != "d" {
		t.Errorf("消している関数を見つけられません: %v", got)
	}
	if got := deletesSystemMetadata(parse("func o() {\n" +
		"_, _ = p.Exec(ctx, `DELETE FROM agents WHERE id = $1`)\n}")); len(got) != 0 {
		t.Errorf("別のテーブルからの消し込みを数えています: %v", got)
	}
	if got := deletesSystemMetadata(parse("func r() {\n" +
		"_ = p.QueryRow(ctx, `SELECT value FROM system_metadata WHERE key = $1`)\n}")); len(got) != 0 {
		t.Errorf("読み取りを消し込みに数えています: %v", got)
	}
}

// **解除の経路が登録されていること。**
//
// 中身がどれだけ揃っていても、router に無ければ gin は 404 を返します。
// 画面の「自動に戻す」は、そこで黙って失敗します。
func TestTheCriticalityClearRouteIsRegistered(t *testing.T) {
	src, err := os.ReadFile("../router.go")
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	want := `ep.DELETE("/:id/criticality", s.handlers.AssetCriticality.ClearManualScore)`
	if !strings.Contains(string(src), want) {
		t.Errorf("`DELETE /endpoints/:id/criticality` が登録されていません。"+
			"**画面の「自動に戻す」はここに届きます** (%s)", want)
	}
}

// **消えた行が、計算値として読み戻されること。**
//
// DELETE そのものは DB が要りますが、**消えたあとの読み方は
// `manualCriticality` が全部決めています** —— 行が無ければ
// `storedCriticality` は「無い」と答え、`computeScoreForAgent` は
// `scoreAgent` に進みます。その計算値に手動の印が付かないことを、
// ここで留めます。
func TestAComputedScoreCarriesNoManualMark(t *testing.T) {
	computed := scoreAgent(criticalityInputs{
		agentID: "a-1", osType: "linux", osVersion: "22.04", status: "online",
	})
	if computed.ManualOverride {
		t.Error("計算値に手動の印が付いています。**解除しても手動のままです**")
	}
	if computed.Reason != "" {
		t.Errorf("計算値が理由を持っています: %q。前の手動設定の理由が残ります", computed.Reason)
	}
}
