package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// pgx reports a mid-iteration failure through rows.Err(), not Next(). Next()
// returns false for a healthy end and a broken one alike, so a handler that
// never asks serves a short page and calls it a complete one. The analyst sees
// a list with no indication that it stops early — which, from the console,
// looks exactly like "that is all there is".
//
// 107 loops in this package did not ask. They do now, and they answer in one of
// two ways, both taken from the handler itself rather than invented here:
//
//   - The handler's own query-error branch returns a response. The rows.Err()
//     check gives the SAME response. Whatever this endpoint already decided a
//     database failure means, a half-read result set means the same thing.
//
//   - The handler's own query-error branch does not return — the loop fills one
//     section of a composite page and the rest is served regardless. Then the
//     rows.Err() check logs and carries on, because failing a page that was
//     built to degrade would be a different change than the one intended.
//
// This test pins the first rule, because getting it wrong is easy and quiet.
// The codemod that made these edits first copied the WRONG guard in ExportCSV —
// an earlier `if err != nil` that validated the ?since= parameter — and so
// answered a database failure with "since は RFC3339 形式で指定してください":
// a 400 telling the operator to fix a request that was fine. Nothing about that
// stands out when skimming the diff.

// checkSite pairs one `if err := v.Err(); ...` with the handler's own guard for
// the query that produced v.
type checkSite struct {
	file  string
	fn    string
	line  int
	v     string
	check *ast.BlockStmt // body of the rows.Err() check
	guard *ast.BlockStmt // body of the handler's query-error branch, nil if none
}

// statusIn returns the first http.StatusXxx named inside n, or "".
func statusIn(n ast.Node) string {
	var found string
	ast.Inspect(n, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok || found != "" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "http" || !strings.HasPrefix(sel.Sel.Name, "Status") {
			return true
		}
		found = sel.Sel.Name
		return true
	})
	return found
}

func endsInReturn(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

// queryGuard finds the `if <e> != nil { ... }` guarding the Query that assigned
// v, searching only between that assignment and limit.
//
// Both bounds matter. Without the lower one this picks up a request-validation
// check that happens to reuse the name `err`; without the upper one it can pick
// up a guard belonging to a later query in the same handler.
func queryGuard(fn *ast.FuncDecl, v string, limit token.Pos) *ast.BlockStmt {
	var errVar string
	var queryEnd token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 2 || len(as.Rhs) != 1 || as.Pos() > limit {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Name != v {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || !strings.HasPrefix(sel.Sel.Name, "Query") {
			return true
		}
		if id, ok := as.Lhs[1].(*ast.Ident); ok && as.End() > queryEnd {
			errVar, queryEnd = id.Name, as.End()
		}
		return true
	})
	if errVar == "" {
		return nil
	}
	var body *ast.BlockStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok || body != nil || is.Init != nil || is.Pos() < queryEnd || is.Pos() > limit {
			return true
		}
		bin, ok := is.Cond.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		x, xok := bin.X.(*ast.Ident)
		y, yok := bin.Y.(*ast.Ident)
		if !xok || !yok || x.Name != errVar || y.Name != "nil" {
			return true
		}
		switch bin.Op {
		case token.NEQ:
			body = is.Body
		case token.EQL:
			// `if err == nil { ...loop... }` — the inverted shape. The handler
			// has no error branch at all: on failure it simply skips the
			// section and serves the page. An empty block stands for that, so
			// the caller sees "found a disposition, and it does not respond".
			body = &ast.BlockStmt{}
		}
		return true
	})
	return body
}

// errCheckOf returns the variable v for `if err := v.Err(); err != nil`.
func errCheckOf(is *ast.IfStmt) string {
	assign, ok := is.Init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return ""
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Err" {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

func collectCheckSites(t *testing.T) []checkSite {
	t.Helper()
	return collectCheckSitesWithFset(t, token.NewFileSet())
}

// collectCheckSitesWithFset は、位置を呼び出し側の fset で数えたいときに
// 使います（一度きりの書き換え道具が、番人の本文を切り出すのに要ります）。
func collectCheckSitesWithFset(t *testing.T, fset *token.FileSet) []checkSite {
	t.Helper()
	var sites []checkSite

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				is, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				v := errCheckOf(is)
				if v == "" {
					return true
				}
				sites = append(sites, checkSite{
					file: filepath.Base(path), fn: fn.Name.Name,
					line: fset.Position(is.Pos()).Line, v: v,
					check: is.Body, guard: queryGuard(fn, v, is.Pos()),
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return sites
}

// The headline: a database failure is never reported as the caller's mistake.
//
// This is the ExportCSV bug stated as a law. A 4xx here says the request was
// wrong, so the operator goes and checks their request — which was fine — while
// the actual failure is in the database. The narrower rule "must exactly match
// the handler's own query-error status" was tried first and rejected: several
// handlers legitimately differ, including one that answers 500 on a truncated
// read while its query-error branch answers 200-empty, which is better than
// what it mirrors. Demanding a match there would mean demanding it be made
// worse.
func TestNoRowsErrCheckBlamesTheCaller(t *testing.T) {
	sites := collectCheckSites(t)
	if len(sites) < 100 {
		t.Fatalf("rows.Err() のチェックが %d 個しか見つかりません。"+
			"このゲートが対象を見失っている可能性があります", len(sites))
	}

	for _, p := range policyProblems(sites) {
		t.Error(p)
	}
}

// blamesTheCaller reports whether a status pins a database failure on the
// request. Kept as its own function so it can be exercised: on the passing path
// nothing here is a 4xx, so the whole condition is unreached and a rule that
// checked nothing at all would look identical.
func blamesTheCaller(status string) bool {
	for _, p := range []string{
		"StatusBad", "StatusUnauthorized", "StatusForbidden",
		"StatusNotFound", "StatusUnprocessable", "StatusConflict",
		"StatusTooManyRequests",
	} {
		if strings.HasPrefix(status, p) {
			return true
		}
	}
	return false
}

// policyProblems applies both rules to a set of sites.
func policyProblems(sites []checkSite) []string {
	var out []string
	for _, s := range sites {
		where := func() string {
			return s.file + ":" + strconv.Itoa(s.line) + " " + s.fn + " (" + s.v + ")"
		}
		status := statusIn(s.check)
		if blamesTheCaller(status) {
			out = append(out, where()+": 結果セットの読み取り失敗に "+status+" を返しています。\n"+
				"  DB 障害を呼び出し側の誤りとして報告することになり、\n"+
				"  運用担当は問題の無いリクエストを疑いに行きます。\n"+
				"  （リクエスト検証側の if err != nil を取り違えると、こうなります）")
		}
		if status != "" && !endsInReturn(s.check) {
			out = append(out, where()+": 応答した後に return していません。二重応答になります")
		}
		// When the handler chose not to end the response on a query failure —
		// the loop fills one section of a composite page and the rest is served
		// regardless — this check must not respond either. The response is
		// decided further down; writing one here makes it a second one.
		if s.guard != nil && !endsInReturn(s.guard) && status != "" {
			out = append(out, where()+": クエリ失敗時は応答せず処理を続けるハンドラなのに、"+
				"rows.Err() だけ "+status+" を返しています。ページ全体の応答と二重になります")
		}
		if len(s.check.List) == 0 {
			out = append(out, where()+": rows.Err() を見ていますが中身が空です")
		}
	}
	sort.Strings(out)
	return out
}

// The rules have to be able to fire. Every branch above is unreached while the
// package is healthy.
func TestThePolicyRulesActuallyFire(t *testing.T) {
	blk := func(src string) *ast.BlockStmt {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nfunc _() {\n"+src+"\n}", 0)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	respond500 := blk(`c.JSON(http.StatusInternalServerError, nil)
return`)
	respond400 := blk(`c.JSON(http.StatusBadRequest, nil)
return`)
	respondNoReturn := blk(`c.JSON(http.StatusInternalServerError, nil)`)
	logOnly := blk(`slog.Warn("x")`)
	empty := blk(``)

	for _, tc := range []struct {
		name string
		site checkSite
		want string
	}{
		{"500 を返して return", checkSite{check: respond500, guard: respond500}, ""},
		{"ログのみ・ハンドラも継続", checkSite{check: logOnly, guard: empty}, ""},
		{"DB障害に 400", checkSite{check: respond400, guard: respond500}, "呼び出し側の誤り"},
		{"応答して return しない", checkSite{check: respondNoReturn, guard: respond500}, "二重応答"},
		{"継続するハンドラで応答", checkSite{check: respond500, guard: empty}, "二重になります"},
		{"中身が空", checkSite{check: empty, guard: respond500}, "中身が空"},
	} {
		got := policyProblems([]checkSite{tc.site})
		if tc.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: 問題なしのはずが %v", tc.name, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: 指摘が %d 件 (want 1): %v", tc.name, len(got), got)
			continue
		}
		if !strings.Contains(got[0], tc.want) {
			t.Errorf("%s: 内容が違います: %s", tc.name, got[0])
		}
	}
}

// queryGuard must recognise both shapes a handler uses to decide what a failed
// query means: the explicit error branch, and `if err == nil { ...loop... }`,
// which has no error branch and simply serves the page without the section.
func TestQueryGuardRecognisesTheInvertedShape(t *testing.T) {
	const src = `package p
func composite(c *ctx) {
	rows2, err := h.pool.Query(ctx, "SELECT 1")
	if err == nil {
		for rows2.Next() {
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("x")
		}
		rows2.Close()
	}
	c.JSON(http.StatusOK, nil)
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	var checkPos token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if is, ok := n.(*ast.IfStmt); ok && errCheckOf(is) == "rows2" {
			checkPos = is.Pos()
		}
		return true
	})
	g := queryGuard(fn, "rows2", checkPos)
	if g == nil {
		t.Fatal("`if err == nil` 形のハンドラで処理方針を見つけられていません。" +
			"この形が見えないと、区画ごとに縮退するハンドラすべてが検査対象から外れます")
	}
	if endsInReturn(g) {
		t.Error("`if err == nil` 形は「応答せず継続」のはずです")
	}
}

// And the comparisons have to be able to fail, or "everything matches" would
// just mean "nothing is compared".
func TestTheStatusComparisonCanFail(t *testing.T) {
	const src = `package p
import "net/http"
func responds() {
	c.JSON(http.StatusInternalServerError, nil)
}
func respondsAndReturns() {
	c.JSON(http.StatusBadRequest, nil)
	return
}
func silent() {
	x := 1
	_ = x
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantStatus := map[string]string{
		"responds": "StatusInternalServerError", "respondsAndReturns": "StatusBadRequest", "silent": "",
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if got := statusIn(fn.Body); got != wantStatus[fn.Name.Name] {
			t.Errorf("%s: statusIn = %q, want %q", fn.Name.Name, got, wantStatus[fn.Name.Name])
		}
		wantRet := fn.Name.Name == "respondsAndReturns"
		if endsInReturn(fn.Body) != wantRet {
			t.Errorf("%s: endsInReturn = %v, want %v", fn.Name.Name, endsInReturn(fn.Body), wantRet)
		}
	}
}

// queryGuard's two bounds are the whole point — this is the bug the codemod
// actually made, reduced to a fixture.
func TestQueryGuardIgnoresARequestValidationCheck(t *testing.T) {
	const src = `package p
func export(c *ctx) {
	if v := c.Query("since"); v != "" {
		t, err := parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, nil)
			return
		}
		_ = t
	}
	rows, err := h.pool.Query(ctx, "SELECT 1")
	if err != nil {
		c.JSON(http.StatusInternalServerError, nil)
		return
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fn := f.Decls[0].(*ast.FuncDecl)

	var checkPos token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if is, ok := n.(*ast.IfStmt); ok && errCheckOf(is) == "rows" {
			checkPos = is.Pos()
		}
		return true
	})
	if checkPos == 0 {
		t.Fatal("fixture の rows.Err() が見つかりません")
	}

	g := queryGuard(fn, "rows", checkPos)
	if g == nil {
		t.Fatal("クエリのガードが見つかりませんでした")
	}
	if got := statusIn(g); got != "StatusInternalServerError" {
		t.Errorf("リクエスト検証の if err != nil を拾っています: %s。"+
			"これを写すと DB 障害に 400 を返します", got)
	}
}
