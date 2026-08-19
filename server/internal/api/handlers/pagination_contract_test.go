package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// 判定そのもの
// ─────────────────────────────────────────────────────────────────────────────

// **範囲外は既定に戻る。0 にはならない。**
//
// これが崩れると、`per_page=0` や `per_page=abc`（Atoi が 0 を返します）が
// 0 件返り、**「該当なし」と見分けが付かなくなります。** 実測ではまさに
// これが `/api/v1/vulnerabilities` で起きていました —— `total` は 120、
// 一覧は空。
func TestClampPerPageNeverReturnsZero(t *testing.T) {
	for _, raw := range []int{-100, -1, 0, 101, 100000} {
		if got := clampPerPage(raw, 20, 100); got != 20 {
			t.Errorf("clampPerPage(%d, 20, 100) = %d, 既定の 20 に戻るはずです", raw, got)
		}
	}
}

// **範囲内はそのまま。** 既定に丸めてしまうと、利用者が選んだ件数が
// 黙って無視されます。
func TestClampPerPageKeepsWhatIsInRange(t *testing.T) {
	for _, raw := range []int{1, 19, 20, 21, 100} {
		if got := clampPerPage(raw, 20, 100); got != raw {
			t.Errorf("clampPerPage(%d, 20, 100) = %d, そのまま通るはずです", raw, got)
		}
	}
}

// **上限そのものは通る。** `> max` であって `>= max` ではありません。
func TestClampPerPageAcceptsTheMaximumItself(t *testing.T) {
	if got := clampPerPage(200, 50, 200); got != 200 {
		t.Errorf("clampPerPage(200, 50, 200) = %d, 上限ちょうどは有効です", got)
	}
	if got := clampPerPage(201, 50, 200); got != 50 {
		t.Errorf("clampPerPage(201, 50, 200) = %d, 上限超えは既定に戻ります", got)
	}
}

// **負のページは 1 に寄る。** 負の OFFSET を Postgres が拒否するので、
// 通すと一覧が丸ごとエラーになります。
func TestClampPageNeverGoesBelowOne(t *testing.T) {
	for _, raw := range []int{-100, -1, 0} {
		if got := clampPage(raw); got != 1 {
			t.Errorf("clampPage(%d) = %d, want 1", raw, got)
		}
	}
	if got := clampPage(7); got != 7 {
		t.Errorf("clampPage(7) = %d, そのまま通るはずです", got)
	}
}

// **OFFSET は負にならない。** 上の2つが効いていれば、どの入力でも
// 0 以上になります。
func TestClampPageParamsNeverProducesANegativeOffset(t *testing.T) {
	for _, page := range []int{-5, 0, 1, 2, 1000} {
		for _, perPage := range []int{-1, 0, 20, 100000} {
			gotPage, gotPerPage, offset := clampPageParams(page, perPage, 20, 100)
			if offset < 0 {
				t.Errorf("clampPageParams(%d, %d) の OFFSET が %d です。"+
					"**Postgres が問い合わせごと拒否します**", page, perPage, offset)
			}
			if gotPerPage < 1 {
				t.Errorf("clampPageParams(%d, %d) の件数が %d です。"+
					"**0 件返って「該当なし」に見えます**", page, perPage, gotPerPage)
			}
			if offset != (gotPage-1)*gotPerPage {
				t.Errorf("clampPageParams(%d, %d): OFFSET %d が page %d / 件数 %d と"+
					"合いません", page, perPage, offset, gotPage, gotPerPage)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ハンドラが本物を呼んでいること
// ─────────────────────────────────────────────────────────────────────────────

// **0件を検査して緑を返すのがいちばん高くつきます。**
//
// 実測 (2026-08-12): 23 か所。床は現在値より少し下に置きます ——
// ぴったりにすると、ハンドラを1つ消しただけで落ちます。
const minPerPageReaders = 20

// scanReachedTheTree — 走査が届いたかの判定そのもの。
//
// **切り出してあるのは、この判定を無効にする変異を殺せるようにするため**
// です。`if scanned < 0` に潰しても、走査は実際には届いているので
// 検査は緑のままでした（変異が生き残りました）。
func scanReachedTheTree(scanned, floor int) bool {
	return scanned >= floor
}

// 床の判定が効くこと。
func TestTheScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if scanReachedTheTree(0, minPerPageReaders) {
		t.Error("**0 件でも「届いた」と言っています。** 走査が壊れた日に、" +
			"全ハンドラが補完している姿と同じ緑を返します")
	}
	if scanReachedTheTree(minPerPageReaders-1, minPerPageReaders) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !scanReachedTheTree(minPerPageReaders, minPerPageReaders) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minPerPageReaders < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}

// isClampCall — 補完を通したと認める呼び出し。
//
// **切り出してあるのは、この一覧を広げる変更を殺せるようにするため**です。
// 全ハンドラが補完を通っている今、`"Atoi"` を足しても件数は変わらず、
// 走査の側では気付けません（実際に変異が生き残りました）。
func isClampCall(name string) bool {
	switch name {
	case "clampPageParams", "clampPerPage", "clampNotificationPage":
		return true
	}
	return false
}

// 認める一覧が広がっていないこと。
func TestOnlyTheRealClampCountsAsClamping(t *testing.T) {
	for _, name := range []string{"clampPageParams", "clampPerPage", "clampNotificationPage"} {
		if !isClampCall(name) {
			t.Errorf("%s を補完と認めていません。**本物を呼んでいるハンドラが"+
				"違反として並びます**", name)
		}
	}
	// **`per_page` を読む関数はどれもこれらを呼びます。** 認めてしまうと、
	// 補完を外しても走査は緑のままです。
	for _, name := range []string{"Atoi", "Query", "DefaultQuery", "ParseInt",
		"ShouldBindJSON", "Param", "JSON", ""} {
		if isClampCall(name) {
			t.Errorf("%q を補完と認めています。**これを呼ぶだけで走査を"+
				"すり抜けられます**", name)
		}
	}
}

// `per_page` の語を含むが、SQL の LIMIT ではないもの。
//
// **走査を狭めずに、理由を書いて外します。** 狭めると、狭めた範囲に
// 入った新しいハンドラが黙って外れます。ここに足すには理由が要ります。
var perPageIsNotAPageSize = map[string]string{
	"settings_handler.go:ListChannels": "応答に `\"per_page\": len(channels)` を" +
		"入れているだけで、要求からは読んでいません。全件返す一覧です。",
	"user_preferences_handler.go:validateItemsPerPage": "画面設定の " +
		"`items_per_page`（1行あたりの表示件数）の検証です。SQL には渡りません。",
}

// **判定を切り出しただけでは足りません。**
//
// 呼ばなくなったら元に戻ります —— 実測前の状態がまさにそれで、
// `vulnerabilities_handler.go` と `training_handler.go` には
// 上限の行そのものがありませんでした。同じ4行が21か所に散っていて、
// 2か所だけ欠けていても誰も気付けません。
//
// ここは `per_page` を読むハンドラが、補完を必ず通ることを留めます。
func TestEveryHandlerThatReadsPerPageClampsIt(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}

	type site struct {
		file string
		fn   string
		line int
	}
	var readers, unclamped []site

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, name, src, parser.ParseComments)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", name, parseErr)
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// 補完そのものを定義しているファイルは対象外。
			if name == "pagination.go" {
				continue
			}
			readsPerPage := false
			clamps := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if strings.Contains(lit.Value, "per_page") {
						readsPerPage = true
					}
				}
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && isClampCall(id.Name) {
						clamps = true
					}
				}
				return true
			})
			if !readsPerPage {
				continue
			}
			s := site{file: name, fn: fn.Name.Name, line: fset.Position(fn.Pos()).Line}
			readers = append(readers, s)
			if !clamps && perPageIsNotAPageSize[name+":"+fn.Name.Name] == "" {
				unclamped = append(unclamped, s)
			}
		}
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	// 実測 (2026-08-12): 23 か所（うち2つは LIMIT ではない。上の表）。
	// 走査が届かなくなると 0 になり、
	// 「全部が補完している」と同じ姿で緑になります。
	if !scanReachedTheTree(len(readers), minPerPageReaders) {
		t.Fatalf("走査が届いていません: `per_page` を読む関数が %d 個しか"+
			"見えません（実測 23、床 %d）", len(readers), minPerPageReaders)
	}

	t.Logf("`per_page` を読む関数: %d 個（うち LIMIT でないもの %d 個）",
		len(readers), len(perPageIsNotAPageSize))

	if len(unclamped) > 0 {
		sort.Slice(unclamped, func(i, j int) bool { return unclamped[i].file < unclamped[j].file })
		for _, s := range unclamped {
			t.Errorf("%s:%d %s が `per_page` を読みながら補完を通していません。"+
				"**0 や負や桁違いがそのまま SQL の LIMIT に入ります**", s.file, s.line, s.fn)
		}
	}
}

// 応答が、実際に使った件数を名乗ること。
//
// **利用者が頼んだ件数と、返した件数が違うことがあります**（範囲外を
// 既定に戻すので）。`per_page` を返さないと、画面は「頼んだ件数で
// 返ってきた」と思い込んで頁送りを組み立てます。
//
// 最初は「関数の中に `"per_page"` という文字列があること」で見て
// いました。**それでは殺せません** —— 同じ関数が
// `c.DefaultQuery("per_page", "50")` で読んでいるので、応答から
// 落としても文字列は残ります（変異が生き残りました）。
// ここは `c.JSON` に渡す `gin.H` の鍵だけを見ます。
func TestListResponsesReportThePageSizeTheyActuallyUsed(t *testing.T) {
	fset := token.NewFileSet()
	// 実測で欠けていた2つ。直したので、戻ったら落ちます。
	want := map[string][]string{
		"vulnerabilities_handler.go": {"List"},
		"training_handler.go":        {"GetResults"},
	}
	for file, fns := range want {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s を読めません: %v", file, err)
		}
		f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s を解析できません: %v", file, err)
		}
		for _, name := range fns {
			found := false
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != name || fn.Body == nil {
					continue
				}
				found = true
				if !respondsWithPageSize(fn.Body) {
					t.Errorf("%s の %s が、応答の gin.H に per_page を"+
						"入れていません。**画面は頼んだ件数で頁送りを"+
						"組み立ててしまいます**", file, name)
				}
			}
			if !found {
				t.Errorf("%s に %s が見つかりません", file, name)
			}
		}
	}
}

// respondsWithPageSize — `c.JSON(..., gin.H{... "per_page": ...})` の鍵を探します。
//
// **要求から読んでいる `"per_page"` と区別するため**に、複合リテラルの
// 鍵の位置だけを見ます。
func respondsWithPageSize(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if lit.Value == `"per_page"` {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// 鍵の探し方が、要求の読み取りを拾っていないこと。
//
// **これが無いと、上の検査は「関数のどこかに per_page があればよい」に
// 戻せます。** 戻した状態でも緑になるので、戻したことに気付けません。
func TestThePageSizeCheckLooksAtTheResponseNotTheRequest(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		src := "package p\nfunc f(c any) {\n" + body + "\n}\n"
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	onlyReads := parse(t, `_ = c.DefaultQuery("per_page", "50")`)
	if respondsWithPageSize(onlyReads) {
		t.Error("要求から読んでいるだけの `\"per_page\"` を、応答に入れたと" +
			"数えています。**応答から落としても緑のままになります**")
	}
	responds := parse(t, `c.JSON(200, gin.H{"per_page": 50})`)
	if !respondsWithPageSize(responds) {
		t.Error("応答の gin.H に入っている `\"per_page\"` を見つけられません")
	}
}
