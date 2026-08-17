package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// **端末に届かなかった指示を「しました」と答えないこと。**
//
// `Isolate` は `_ = h.Commander.IsolateEndpoint(…)` で送信結果を捨てて、
// 「エージェントを隔離しました」と答えていました。DB は `isolated` に
// なるので画面もそう見えますが、**指示が届いていなければ端末は
// ネットワークに繋がったままです。**
//
// ハートビートには巻き戻しが片側しかありません。実測 (2026-08-12):
//
//	should_unisolate  あり —— 端末が「まだ隔離中」と言い、DB が解除済み
//	                  なら、次のハートビートで解除されます
//	should_isolate    **ありません**
//
// つまり**隔離の送信が失敗したら、その端末は二度と隔離されません。**
// 解除の方は次のハートビートが直すので、跡を残すだけで足ります ——
// **同じ形に見えて、答え方が違います。**
//
// `Commander` は具象型（`*store.CommandStore`）なので、失敗する
// 差し替えを渡す検査は書けません。ここは呼び出しの形を見ます:
// **error を見ていること・5xx で答えること・そこで戻ること。**

// deliverySite is one place a handler pushes a command to an endpoint.
type deliverySite struct {
	file, fn      string
	line          int
	checksErr     bool // `if err := …; err != nil`
	answersFailed bool // 5xx を返す
	returns       bool
}

func (s deliverySite) String() string {
	return fmt.Sprintf("%s:%d %s", s.file, s.line, s.fn)
}

// **指示そのものの送信**。記録ではありません。
var commandDeliveryCalls = map[string]bool{
	"IsolateEndpoint": true,
	"RestoreFile":     true,
}

// **巻き戻しがある送信。**
//
// 実測 (2026-08-12): 最初は解除だけでした。`should_isolate` を両側
// （サーバの HTTP と gRPC、端末の Reporter）に足したので、隔離も
// ここに入ります —— **DB が唯一の真実**になり、指示の送信は速い経路、
// 届かなければ 30 秒後のハートビートが直します。
//
// **それでも隔離は 5xx で答えます。** 直るまで最大 30 秒あり、その間
// 対応する人は「封じ込め済み」と思って次に進みます —— 封じ込めは、
// 遅れて効いた分だけ遅れて効いていません。
var deliveryHasFallback = map[string]bool{
	"UnisolateEndpoint": true,
	"IsolateEndpoint":   true,
}

// deliveryProblems is the judgement, kept apart from the scan because on a
// passing tree it never pushes.
func deliveryProblems(sites []deliverySite) []string {
	var out []string
	for _, s := range sites {
		if !s.checksErr {
			out = append(out, fmt.Sprintf(
				"%s が送信の失敗を見ていません。**届かなくても"+
					"「しました」と答えます**", s))
			continue
		}
		if !s.answersFailed {
			out = append(out, fmt.Sprintf(
				"%s が失敗を 5xx で答えていません。**DB と画面は"+
					"「実行済み」、端末は何も受け取っていません**", s))
		}
		if !s.returns {
			out = append(out, fmt.Sprintf(
				"%s が失敗のあと戻っていません。**後続が成功として"+
					"進みます**", s))
		}
	}
	sort.Strings(out)
	return out
}

func commandDeliverySites(t *testing.T, files ...string) []deliverySite {
	t.Helper()
	var out []deliverySite
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("%s を parse できません: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || ifs.Init == nil {
					return true
				}
				as, ok := ifs.Init.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 {
					return true
				}
				call, ok := as.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !commandDeliveryCalls[sel.Sel.Name] {
					return true
				}
				out = append(out, deliverySite{
					file: path, fn: fn.Name.Name, line: fset.Position(ifs.Pos()).Line,
					checksErr:     isErrNotNilCond(ifs.Cond),
					answersFailed: answersServerError(ifs.Body),
					returns:       hasBareReturn(ifs.Body),
				})
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// isErrNotNilCond — `err != nil` か。**`== nil` に反転されると、届いた回を
// 失敗として扱い、届かなかった回は素通りします。**
func isErrNotNilCond(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	y, ok := bin.Y.(*ast.Ident)
	return ok && y.Name == "nil"
}

func answersServerError(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		st, ok := call.Args[0].(*ast.SelectorExpr)
		if ok && serverErrorStatusNames[st.Sel.Name] {
			found = true
		}
		return true
	})
	return found
}

// 5xx なら何でもよい。**500 だけを見ていると、より正確な札を貼った実装が
// 「失敗を答えていない」と報告されます** —— 指示が端末に届かなかったのは
// 上流の失敗なので 502 のほうが正確で、#690 はそう答えている。
// 判定したいのは「サーバ側の失敗として答えたか」であって、番号ではない。
var serverErrorStatusNames = map[string]bool{
	"StatusInternalServerError": true, // 500
	"StatusNotImplemented":      true, // 501
	"StatusBadGateway":          true, // 502
	"StatusServiceUnavailable":  true, // 503
	"StatusGatewayTimeout":      true, // 504
}

func hasBareReturn(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		if r, ok := n.(*ast.ReturnStmt); ok && len(r.Results) == 0 {
			found = true
		}
		return true
	})
	return found
}

// 実測 (2026-08-12): 3つ。隔離、`agents_handler` のファイル復元、
// 検疫画面からのファイル復元です。**`agents_handler` の復元は最初から
// 正しく答えていました** —— 同じ送信でも、答え方が場所によって違って
// いたということです。
//
// 3 → 2 (#757 の取り込み)。隔離と隔離解除は Gatekeeper 経由になり、この
// ファイルが見ている「ハンドラから直接コマンドを送る」形ではなくなった。
// 送信失敗の扱いは isolation 側と agents_isolate_dispatch_test.go が留める。
// 残る 2 つは、どちらもファイル復元。
const commandDeliverySiteCount = 2

func TestACommandThatDidNotReachTheEndpointIsNotAnsweredWithSuccess(t *testing.T) {
	sites := commandDeliverySites(t, "agents_handler.go", "quarantine_handler.go")
	if len(sites) != commandDeliverySiteCount {
		t.Errorf("指示の送信が %d か所です（留めているのは %d）: %v",
			len(sites), commandDeliverySiteCount, sites)
	}
	for _, p := range deliveryProblems(sites) {
		t.Error(p)
	}
}

// 判定が動くこと。通る木では何も push しません。
func TestTheCommandDeliveryRuleActuallyFires(t *testing.T) {
	for _, c := range []struct {
		name string
		s    deliverySite
		want int
	}{
		{"全部している", deliverySite{checksErr: true, answersFailed: true, returns: true}, 0},
		{"error を見ていない", deliverySite{answersFailed: true, returns: true}, 1},
		{"5xx で答えない", deliverySite{checksErr: true, returns: true}, 1},
		{"戻らない", deliverySite{checksErr: true, answersFailed: true}, 1},
		{"どれもしていない", deliverySite{}, 1},
	} {
		if got := deliveryProblems([]deliverySite{c.s}); len(got) != c.want {
			t.Errorf("%s: %d件 (want %d): %v", c.name, len(got), c.want, got)
		}
	}

	// 条件の向き。**`== nil` に反転すると、届いた回を失敗にします。**
	parse := func(src string) ast.Expr {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\nif "+src+" {\n}\n}\n", 0)
		if err != nil {
			t.Fatalf("見本: %v", err)
		}
		var out ast.Expr
		ast.Inspect(f, func(n ast.Node) bool {
			if ifs, ok := n.(*ast.IfStmt); ok && out == nil {
				out = ifs.Cond
			}
			return true
		})
		return out
	}
	if !isErrNotNilCond(parse("err != nil")) {
		t.Error("`err != nil` を読めていません")
	}
	if isErrNotNilCond(parse("err == nil")) {
		t.Error("**`err == nil` を通しています。** 届いた回を失敗として" +
			"扱い、届かなかった回が素通りします")
	}

	// **両方向に巻き戻しがあること。** 片方だけだと、直る失敗と
	// 直らない失敗ができます。
	for _, k := range []string{"IsolateEndpoint", "UnisolateEndpoint"} {
		if !deliveryHasFallback[k] {
			t.Errorf("%s の巻き戻しがありません", k)
		}
	}
}

// **ハートビートが両方向に巻き戻すこと。**
//
// 元は `should_unisolate` だけでした —— 隔離コマンドが届かなかった端末を
// 直すものが、何もありませんでした。両方向にしたので、**DB が唯一の
// 真実**になります。
//
// 片方が消えたらここで落ちます。**片側だけの巻き戻しは、直る失敗と
// 直らない失敗を作ります。**
func TestTheHeartbeatReconcilesIsolationBothWays(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "agents_handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var hasUnisolate, hasIsolate bool
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		switch lit.Value {
		case `"should_unisolate"`:
			hasUnisolate = true
		case `"should_isolate"`:
			hasIsolate = true
		}
		return true
	})
	if !hasUnisolate {
		t.Error("`should_unisolate` が見つかりません。**解除コマンドが" +
			"届かなかった端末を直すものが無くなります**")
	}
	if !hasIsolate {
		t.Error("`should_isolate` が見つかりません。**隔離コマンドが" +
			"届かなかった端末は、二度と隔離されません** —— DB と画面は" +
			"「隔離済み」のままです")
	}
}

// **突き合わせが両方向あること。** 元は片方向だけで、隔離コマンドが
// 端末に届かなかったとき、それを直すものが何もありませんでした。
func TestReconcileIsolationGoesBothWays(t *testing.T) {
	for _, c := range []struct {
		name, db, reported string
		iso, uniso         bool
	}{
		{"DB は隔離、端末は繋がっている", "isolated", "online", true, false},
		{"DB は解除、端末は隔離中", "online", "isolated", false, true},
		{"どちらも隔離", "isolated", "isolated", false, false},
		{"どちらも通常", "online", "online", false, false},
		{"端末が error を報告", "isolated", "error", true, false},
		{"DB が inactive", "inactive", "isolated", false, true},
	} {
		iso, uniso := reconcileIsolation(c.db, c.reported)
		if iso != c.iso || uniso != c.uniso {
			t.Errorf("%s: isolate=%v unisolate=%v, want %v/%v。"+
				"**片方向だけだと、直る失敗と直らない失敗ができます**",
				c.name, iso, uniso, c.iso, c.uniso)
		}
		if iso && uniso {
			t.Errorf("%s: 両方を指示しています", c.name)
		}
	}
}
