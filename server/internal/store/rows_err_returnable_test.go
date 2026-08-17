package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// **`error` を返せる関数が、`rows.Err()` を捨てないこと。**
//
// `rows.Next()` のループを抜けたあと、`rows.Err()` には「全部読み切ったのか、
// 途中で切れたのか」が入っています。呼び出し側にエラーを返せる関数が
// そこを警告ログに落として `nil` を返すと、**途中までの結果が「全部」として
// 呼び出し側へ渡ります。**
//
// `internal/api/handlers` には別の規則があります（`rows_err_policy_test.go`
// —— そのハンドラ自身がクエリ失敗にどう答えるかに合わせる）。ここは
// **その外側**、`error` を返す関数だけを見ます。答え方に迷いがありません
// —— 返せるのだから返します。
//
// 実測 (2026-08-12)。`internal/api/handlers` の外:
//
//	rows.Err() の箇所      208（文字で数えたとき）
//	  報告している         162
//	  捨てている            46
//	    うち error を返せる  3   ← 文字での数え方ではここまで
//
// **構文木で数え直したら 7 でした。** 文字の探し方では
// `if err = rows.Err()` や複数行に折れた形が漏れます。以下は 7 件全部です:
//
//   - `suppression/engine.go LoadFromDB` —— 途中までのルールで稼働セットを
//     置き換え、`LastLoad().Loaded` にその件数を「読み込めた件数」として
//     記録していました。**抑制したはずのルールが効いていないことに、
//     気づく手掛かりがありません。**
//   - `detection/anomaly_detector.go LoadBaselinesFromDB` —— 途中までの
//     ベースラインで異常判定を始め、"loaded baselines count=N" が全件
//     読めたときと同じ姿で出ていました。
//   - `detection/anomaly.go DetectAnomalies` —— 途中までの候補で「異常なし」
//     を返していました。
//   - `detectionmetrics/tracker.go Calculate` / `GetMITRECoverage` ——
//     途中までのルールで **MITRE の網羅率**を出していました。読めなかった
//     分だけカバーが薄く見えるので、**直す判断を誤らせます。**
//   - `processtree/builder.go BuildTree` —— 親が読めていない子が根として
//     並び、**攻撃の連鎖がそこで切れて見えます。**
//   - `reports/generator.go GenerateThreatSummary` —— 途中までの集計で
//     レポートを作っていました。レポートは配られ、誰も数え直しません。
//
// 残り 39 は `error` を返さない関数（バックグラウンドの繰り返し処理）です。
// そちらは `fail(ctx, err, ...)` で報告するのがこの配備の作法で、
// **答え方の判断が要る**ので、ここでは数えません。

// **`internal/api/handlers` は対象外です。** あちらは別の規則を持っています。
const rowsErrReturnableSkip = "api/handlers"

const rowsErrReturnableRoot = ".."

// 実測 (2026-08-12): `internal/api/handlers` を除いて 308 個。床は下に。
const minRowsErrReturnableFiles = 250

// 実測 (2026-08-12): `error` を返す関数の中の `rows.Err()` は 173 箇所。
const minReturnableRowsErrSites = 140

// **上限ではなく 0 です。** 返せるのだから返します。
const rowsErrReturnableCeiling = 0

func scanReached(scanned, floor int) bool { return scanned >= floor }

func TestTheReturnableScanFloorsNoticeAnEmptyWalk(t *testing.T) {
	for _, floor := range []int{minRowsErrReturnableFiles, minReturnableRowsErrSites, minVoidRowsErrSites} {
		if scanReached(0, floor) {
			t.Errorf("床 %d で、0 でも「届いた」と言っています", floor)
		}
		if !scanReached(floor, floor) {
			t.Errorf("床 %d ちょうどで「届いていない」と言っています", floor)
		}
		if floor < 1 {
			t.Fatalf("床が %d です。**どんな走査も通ります**", floor)
		}
	}
}

// returnsError — その関数が呼び出し側に error を返せるか。
//
// **切り出してあるのは、判定を緩める変更を殺せるようにするため**です。
func returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, r := range fn.Type.Results.List {
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			return true
		}
	}
	return false
}

func TestReturnsErrorLooksAtTheSignature(t *testing.T) {
	parse := func(t *testing.T, sig string) *ast.FuncDecl {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\n"+sig+" {}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl)
	}
	for _, sig := range []string{
		"func f() error",
		"func f() (int, error)",
		"func (r *R) Load(ctx context.Context) error",
	} {
		if !returnsError(parse(t, sig)) {
			t.Errorf("%q が error を返すと見ていません。**返せる関数が"+
				"走査から外れます**", sig)
		}
	}
	for _, sig := range []string{"func f()", "func f() int", "func (r *R) run(ctx context.Context)"} {
		if returnsError(parse(t, sig)) {
			t.Errorf("%q を error を返すと数えています", sig)
		}
	}
}

// discardsRowsErr — その分岐が失敗を先へ渡さずに済ませているか。
func discardsRowsErr(block *ast.BlockStmt) bool {
	if block == nil {
		return true
	}
	reported := false
	ast.Inspect(block, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ReturnStmt:
			reported = true
		case *ast.FuncLit:
			return false
		}
		return !reported
	})
	return !reported
}

func TestDiscardsRowsErrTellsLoggingFromReturning(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	if !discardsRowsErr(parse(t, `slog.Warn("row iteration error", "error", err)`)) {
		t.Error("**ログに書くだけを「報告した」と数えています。** " +
			"これがまさに、途中までの結果が「全部」として返る形です")
	}
	if discardsRowsErr(parse(t, `return err`)) {
		t.Error("返しているのに「捨てた」と数えています")
	}
	if !discardsRowsErr(parse(t, `go func() { return }()`)) {
		t.Error("**中の関数の return を、この関数から返すことと取り違えています。**")
	}
	if !discardsRowsErr(nil) {
		t.Error("中身が無いものを「報告した」と数えています")
	}
}

func isRowsErrCheck(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Err" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && strings.Contains(strings.ToLower(id.Name), "rows")
}

func TestFunctionsThatCanReturnAnErrorDoNotDiscardRowsErr(t *testing.T) {
	fset := token.NewFileSet()
	type site struct {
		file string
		fn   string
		line int
	}
	var bad []site
	files, checks := 0, 0

	err := filepath.WalkDir(rowsErrReturnableRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, rowsErrReturnableRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if strings.HasPrefix(rel, rowsErrReturnableSkip) {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		files++
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", rel, parseErr)
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !returnsError(fn) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				is, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				as, ok := is.Init.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 || !isRowsErrCheck(as.Rhs[0]) {
					return true
				}
				checks++
				if discardsRowsErr(is.Body) {
					bad = append(bad, site{rel, fn.Name.Name, fset.Position(is.Pos()).Line})
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !scanReached(files, minRowsErrReturnableFiles) {
		t.Fatalf("走査が届いていません: %d ファイルしか見えません（実測 308、床 %d）",
			files, minRowsErrReturnableFiles)
	}
	if !scanReached(checks, minReturnableRowsErrSites) {
		t.Fatalf("走査が届いていません: `error` を返す関数の中の `rows.Err()` が"+
			"%d 箇所しか見えません（実測 173、床 %d）", checks, minReturnableRowsErrSites)
	}
	t.Logf("走査: %d ファイル / `error` を返す関数の中の `rows.Err()`: %d 箇所",
		files, checks)

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	if len(bad) > rowsErrReturnableCeiling {
		for _, s := range bad {
			t.Errorf("%s:%d %s は `error` を返せるのに、行の読み出しの失敗を"+
				"捨てています。**途中までの結果が「全部」として呼び出し側へ"+
				"渡ります**", s.file, s.line, s.fn)
		}
		t.Errorf("捨てている箇所が %d です（上限 %d）",
			len(bad), rowsErrReturnableCeiling)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// `error` を返せない関数
// ─────────────────────────────────────────────────────────────────────────────

// **返せない関数でも、黙るのは駄目です。**
//
// バックグラウンドの繰り返し処理は `error` を返しません。返す先が無いので、
// 唯一の出口はログと計測です。**そこを `slog.Warn` にしておくと、
// 運用の設定で最初に切られる段になります** —— 「回っているが何もできて
// いない」が、外からは「静かに動いている」と同じ姿になります。
//
// 実測 (2026-08-12): `error` を返さない関数の中で `rows.Err()` を捨てて
// いた箇所は **44**。うち 28 は `internal/scheduler` で、**同じ関数が
// すでに `fail(ctx, err, ...)` を呼んでいました** —— 報告の仕方を知って
// いるのに、この分岐だけが `slog.Warn` でした。
//
// `fail` は `edr_scheduler_failures_total` と `last_success` に落ちるので、
// 「この回は仕事を終えられなかった」が外から見えます
// （`internal/scheduler/heartbeat.go`）。
//
// scheduler の外には `fail` がありません。そちらは `slog.Error` です ——
// **少なくとも、切られない段に置きます。**
//
// ── ここが留めないこと ────────────────────────────────────────────
//
// **途中まで読んだ結果を、そのまま状態として据え置く**問題は残ります。
// `threatintel/feed.go LoadFromDB` は行ごとに `m.feeds` を書き換えるので、
// 途中で切れると**半分だけ新しい**集合が残ります。直すには「新しい集合を
// 作って、成功したときだけ差し替える」形にする必要があり、それは
// `docs/判断待ちの一覧.md` に置いてあります。

// reportsFailure — その分岐が、誰かに届く形で報告しているか。
//
// **切り出してあるのは、判定を緩める変更を殺せるようにするため**です。
func reportsFailure(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = true
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "fail" {
				found = true
			}
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				// **届き先は2つの綴りがあります。** `internal/scheduler` は
				// package 内の `fail`、その外は `tick.Fail` です。片方だけを
				// 認めると、もう片方で書かれた報告が「届いていない」に
				// 数えられます（実際に落ちました）。
				if pkg.Name == "tick" && sel.Sel.Name == "Fail" {
					found = true
				}
				if pkg.Name == "slog" && sel.Sel.Name == "Error" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func TestReportsFailureTellsWarnFromReporting(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	if reportsFailure(parse(t, `slog.Warn("row iteration error", "error", err)`)) {
		t.Error("**`slog.Warn` を報告と数えています。** " +
			"運用の設定で最初に切られる段です —— 「回っているが何もできて" +
			"いない」が見えなくなります")
	}
	if reportsFailure(parse(t, `slog.Debug("x")`)) {
		t.Error("`slog.Debug` を報告と数えています")
	}
	if reportsFailure(parse(t, `_ = err`)) {
		t.Error("何もしないものを報告と数えています")
	}
	if !reportsFailure(parse(t, `fail(ctx, err, "走査が途中で終わりました")`)) {
		t.Error("**`fail` を報告と見ていません。** これが scheduler の出口です")
	}
	if !reportsFailure(parse(t, `tick.Fail(ctx, err, "走査が途中で終わりました")`)) {
		t.Error("**`tick.Fail` を報告と見ていません。** これが scheduler の" +
			"外の出口です —— 片方だけ認めると、もう片方で書かれた報告が" +
			"「届いていない」に数えられます")
	}
	if reportsFailure(parse(t, `tick.Failing(ctx)`)) {
		t.Error("`tick` の別の関数を報告と数えています")
	}
	if !reportsFailure(parse(t, `slog.Error("走査が途中で終わりました", "error", err)`)) {
		t.Error("`slog.Error` を報告と見ていません")
	}
	if !reportsFailure(parse(t, `return`)) {
		t.Error("戻っているのに報告していないと数えています")
	}
	if reportsFailure(parse(t, `go func() { slog.Error("x") }()`)) {
		t.Error("**中の関数を、この関数がしたことと取り違えています。**")
	}
	if reportsFailure(nil) {
		t.Error("中身が無いものを報告と数えています")
	}
}

// isVoidFunc — 「返す先が無い」関数か。
//
// **切り出してあるのは、選び方を反転させる変異を殺せるようにするため**
// です。反転させると `error` を返す関数の方を見ることになり、そちらは
// 別の検査（上）が上限0で見ているので、**違反が出ないまま緑になります。**
func isVoidFunc(fn *ast.FuncDecl) bool { return !returnsError(fn) }

func TestIsVoidFuncPicksTheOnesWithNowhereToReturn(t *testing.T) {
	parse := func(t *testing.T, sig string) *ast.FuncDecl {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+sig+" {}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl)
	}
	for _, sig := range []string{"func f()", "func (d *D) tick(ctx context.Context)"} {
		if !isVoidFunc(parse(t, sig)) {
			t.Errorf("%q を「返す先が無い」と見ていません。**その関数が"+
				"走査から外れます**", sig)
		}
	}
	for _, sig := range []string{"func f() error", "func f() (int, error)"} {
		if isVoidFunc(parse(t, sig)) {
			t.Errorf("%q を「返す先が無い」に数えています。**上の検査と"+
				"同じものを見ることになり、違反が出ないまま緑になります**", sig)
		}
	}
}

// unreportedVoidSites — 1ファイルぶんの違反を集めます。
//
// **切り出してあるのは、集める側を潰す変異を殺せるようにするため**です。
// いま違反は 0 件なので、`if false` に潰しても結果は変わりません
// （変異が生き残りました）。合成した見本で試します。
func unreportedVoidSites(f *ast.File, fset *token.FileSet, rel string) (sites []voidSite, checks int) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isVoidFunc(fn) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			is, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			as, ok := is.Init.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || !isRowsErrCheck(as.Rhs[0]) {
				return true
			}
			checks++
			if !reportsFailure(is.Body) {
				sites = append(sites, voidSite{rel, fn.Name.Name, fset.Position(is.Pos()).Line})
			}
			return true
		})
	}
	return sites, checks
}

type voidSite struct {
	file string
	fn   string
	line int
}

// 集める側が効くこと。**違反する見本を食わせて確かめます。**
func TestUnreportedVoidSitesFindsTheRealThing(t *testing.T) {
	src := `package p

func silent() {
	if err := rows.Err(); err != nil {
		slog.Warn("走査が途中で終わりました", "error", err)
	}
}

func loud() {
	if err := rows.Err(); err != nil {
		slog.Error("走査が途中で終わりました", "error", err)
	}
}

func canReturn() error {
	if err := rows.Err(); err != nil {
		slog.Warn("走査が途中で終わりました", "error", err)
	}
	return nil
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("見本を解析できません: %v", err)
	}
	sites, checks := unreportedVoidSites(f, fset, "x.go")
	if checks != 2 {
		t.Errorf("見た `rows.Err()` = %d 箇所, 2件を期待。**`error` を返す方は"+
			"別の検査の担当です**", checks)
	}
	if len(sites) != 1 {
		t.Fatalf("違反 = %d 件, 1件を期待。**1件も挙げないなら、この検査は"+
			"何も留めていません**: %+v", len(sites), sites)
	}
	if sites[0].fn != "silent" {
		t.Errorf("挙がった違反 = %s, want silent", sites[0].fn)
	}
}

// 実測 (2026-08-12): `error` を返さない関数の中の `rows.Err()` は 57 箇所。
// （44 は文字での数え方。構文木ではこちらです。）
const minVoidRowsErrSites = 45

// **上限ではなく 0 です。** 返せなくても、黙る理由にはなりません。
const voidRowsErrCeiling = 0

func TestFunctionsThatCannotReturnAnErrorStillReportRowsErr(t *testing.T) {
	fset := token.NewFileSet()
	var bad []voidSite
	checks := 0

	err := filepath.WalkDir(rowsErrReturnableRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, rowsErrReturnableRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if strings.HasPrefix(rel, rowsErrReturnableSkip) {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		sites, n := unreportedVoidSites(f, fset, rel)
		bad = append(bad, sites...)
		checks += n
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !scanReached(checks, minVoidRowsErrSites) {
		t.Fatalf("走査が届いていません: `error` を返さない関数の中の `rows.Err()` が"+
			"%d 箇所しか見えません（実測 57、床 %d）", checks, minVoidRowsErrSites)
	}
	t.Logf("`error` を返さない関数の中の `rows.Err()`: %d 箇所", checks)

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	if len(bad) > voidRowsErrCeiling {
		for _, s := range bad {
			t.Errorf("%s:%d %s が、行の読み出しの失敗を誰にも届かない形で"+
				"済ませています。**`fail(ctx, err, ...)`（scheduler）か "+
				"`slog.Error` を使ってください** —— `slog.Warn` は運用で"+
				"最初に切られる段です", s.file, s.line, s.fn)
		}
		t.Errorf("届いていない箇所が %d です（上限 %d）", len(bad), voidRowsErrCeiling)
	}
}
