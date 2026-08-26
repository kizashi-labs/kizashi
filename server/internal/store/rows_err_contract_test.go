package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pgx reports a mid-iteration failure through rows.Err(), not through Next().
// Next() simply returns false — the same thing it returns at the end of a
// healthy result set — so a loop that never asks ends early and hands back a
// short list as though it were the whole thing.
//
// That is the quietest failure in this package. There is no error to log, no
// exception, no partial-result flag: the caller receives a well-formed slice
// and every layer above it behaves normally. In a store that backs an EDR
// console, the short list is the agent that does not appear in the fleet, the
// enabled detection rule that is not loaded, the IOC that is not matched
// against, the alert that is not in the analyst's queue. Each of those reads,
// from the outside, exactly like "there is nothing there".
//
// 219 loops across internal/ did not ask: 74 in store, 107 in api/handlers, 38
// in scheduler. They all do now, so this is a contract rather than a ceiling —
// it fails on a new unchecked loop anywhere under internal/, and because the
// allowlist is empty, on a stale allowlist entry too.

// knownUncheckedRowLoops names loops that iterate a pgx result set without
// consulting rows.Err(), each with what a truncated result would mean.
//
// It is deliberately empty. An entry here is a live defect with a note
// attached, not a waiver — if one is added, it should say what a short result
// costs the operator, and it should be removed by fixing the loop.
var knownUncheckedRowLoops = map[string]string{}

// rowLoop identifies one `for x.Next()` loop.
type rowLoop struct {
	file string
	fn   string
	line int
	v    string
}

func (l rowLoop) key() string { return fmt.Sprintf("%s:%s:%s", l.file, l.fn, l.v) }

// findRowLoops walks a directory's non-test Go files and returns every
// `for x.Next()` loop whose x never has Err() consulted anywhere in the
// enclosing function.
//
// Consulting anywhere in the function, rather than immediately after the loop,
// is deliberate: some callers check inside a helper closure or before an early
// return, and demanding one exact shape would push people to satisfy the gate
// rather than the contract.
func findRowLoops(t *testing.T, dir string) []rowLoop {
	t.Helper()
	fset := token.NewFileSet()
	var out []rowLoop

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
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
				fs, ok := n.(*ast.ForStmt)
				if !ok {
					return true
				}
				v := nextReceiver(fs)
				if v == "" || consultsErr(fn.Body, v) {
					return true
				}
				out = append(out, rowLoop{
					file: filepath.Base(path),
					fn:   fn.Name.Name,
					line: fset.Position(fs.Pos()).Line,
					v:    v,
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// nextReceiver returns x for `for x.Next() { ... }`, or "" for any other loop.
//
// Requiring the for-statement shape is what keeps gin's c.Next() and every
// other unrelated Next method out of the results.
func nextReceiver(f *ast.ForStmt) string {
	call, ok := f.Cond.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Next" {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// rowsErrGuards names helpers whose whole body is the check this contract asks
// for — currently api/handlers.abortOnRowsErr, which calls rows.Err() and
// answers 500 rather than serving the short list. Handing the loop variable to
// one of them consults the error just as much as writing `rows.Err()` inline
// does; without this the gate would fail the call sites that use the helper and
// push them back to hand-rolled checks, which is the opposite of the point.
var rowsErrGuards = map[string]bool{"abortOnRowsErr": true}

func consultsErr(scope ast.Node, v string) bool {
	found := false
	ast.Inspect(scope, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := c.Fun.(*ast.Ident); ok && rowsErrGuards[id.Name] {
			for _, arg := range c.Args {
				if a, ok := arg.(*ast.Ident); ok && a.Name == v {
					found = true
				}
			}
			return true
		}
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != "Err" {
			return true
		}
		if id, ok := s.X.(*ast.Ident); ok && id.Name == v {
			found = true
		}
		return true
	})
	return found
}

// reportRowLoops is separated out for the same reason compareToCeilings is: on
// the passing path the allowlist is empty and there are no findings, so both
// branches below are unreached and a gate that reported nothing at all would
// look identical to one that had nothing to report.
func reportRowLoops(loops []rowLoop, allowlist map[string]string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, l := range loops {
		seen[l.key()] = true
		if _, waived := allowlist[l.key()]; waived {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"%s:%d %s が %s.Err() を見ていません。\n"+
				"  途中で失敗した反復は短い結果を残し、正常な結果と区別がつきません。\n"+
				"  エラー戻り値があるなら返す、ハンドラならクエリ失敗時と同じ応答、\n"+
				"  定期実行なら何が欠けるかを記録する — どれかを選んでください。\n"+
				"  どれも選べないなら knownUncheckedRowLoops に\n"+
				"  「短い結果が運用上どう見えるか」を書いて残してください。",
			l.file, l.line, l.fn, l.v))
	}
	// A stale entry is as much of a problem as a missing check: it says a defect
	// is live when it has been fixed, and the next reader trusts it.
	for key := range allowlist {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf(
				"knownUncheckedRowLoops の %q は既に解消されています。削除してください", key))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestTheRowLoopReportActuallyReports(t *testing.T) {
	bad := rowLoop{file: "agents.go", fn: "ListAgents", line: 415, v: "rows"}
	waived := rowLoop{file: "legacy.go", fn: "Scan", line: 9, v: "rows"}
	allow := map[string]string{waived.key(): "既知: 一覧が途中で切れる"}

	for _, tc := range []struct {
		name  string
		loops []rowLoop
		allow map[string]string
		want  int
		must  string
	}{
		{"問題なし", nil, nil, 0, ""},
		{"未確認のループ", []rowLoop{bad}, nil, 1, "ListAgents"},
		{"許可済みのループ", []rowLoop{waived}, allow, 0, ""},
		{"許可済み1件＋新規1件", []rowLoop{waived, bad}, allow, 1, "ListAgents"},
		{"許可リストが古い（もう存在しない）", nil, allow, 1, "解消されています"},
	} {
		got := reportRowLoops(tc.loops, tc.allow)
		if len(got) != tc.want {
			t.Errorf("%s: %d件, want %d: %v", tc.name, len(got), tc.want, got)
			continue
		}
		if tc.must != "" && !strings.Contains(got[0], tc.must) {
			t.Errorf("%s: 内容が違います: %s", tc.name, got[0])
		}
	}
}

// The gate must actually be looking at something. A refactor that renamed the
// files, or a walk that silently found nothing, would leave the test above
// passing vacuously — the exact failure mode this whole family of tests exists
// to catch.
func TestTheRowLoopScannerFindsTheLoopsItShould(t *testing.T) {
	fset := token.NewFileSet()
	var total int
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if fs, ok := n.(*ast.ForStmt); ok && nextReceiver(fs) != "" {
				total++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if total < 100 {
		t.Errorf("結果セットを走査するループが %d 個しか見つかりません。"+
			"ゲートが対象を見失っている可能性があります", total)
	}
}

// And the detector has to be able to say no, or "everything checks its errors"
// would just mean "the detector never fires".
func TestTheRowLoopDetectorRecognisesAnUncheckedLoop(t *testing.T) {
	const src = `package p
func checked(rows R) error {
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}
func unchecked(rows R) error {
	for rows.Next() {
	}
	return nil
}
func twoSets(a, b R) error {
	for a.Next() {
	}
	if err := a.Err(); err != nil {
		return err
	}
	for b.Next() {
	}
	return nil
}
func notAResultSet(c *ginContext) {
	c.Next()
}
func viaGuard(c *ginContext, rows R) {
	for rows.Next() {
	}
	if abortOnRowsErr(c, rows, "Something") {
		return
	}
}
func guardOnTheWrongSet(c *ginContext, a, b R) {
	for b.Next() {
	}
	if abortOnRowsErr(c, a, "Something") {
		return
	}
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]string{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			fs, ok := n.(*ast.ForStmt)
			if !ok {
				return true
			}
			if v := nextReceiver(fs); v != "" && !consultsErr(fn.Body, v) {
				got[fn.Name.Name] = v
			}
			return true
		})
	}

	want := map[string]string{
		"unchecked": "rows",
		"twoSets":   "b",
		// The guard has to be read as narrowly as `rows.Err()` is: it covers the
		// result set it was handed, not whichever one happens to be in scope.
		"guardOnTheWrongSet": "b",
	}
	if len(got) != len(want) {
		t.Fatalf("検出結果が想定と違います: got=%v want=%v", got, want)
	}
	for fn, v := range want {
		if got[fn] != v {
			t.Errorf("%s: got %q want %q", fn, got[fn], v)
		}
	}
}

// ─── the rest of internal/ ────────────────────────────────────────────────────
//
// Every package under internal/ is now at zero, so this is a contract rather
// than a ceiling: a `for rows.Next()` anywhere that never asks rows.Err() fails
// here, wherever it is.
//
// The answers differ by layer, and all of them came from the code rather than
// from a rule imposed on it. A store returns the error. A handler gives the
// response its own query-error branch already gives. A scheduler logs what will
// be missing and lets the next tick pick it up — except where a watermark or a
// rule-set install would record the partial pass as complete, which is not a
// delay but a permanent gap. What is not allowed anywhere is the fourth answer:
// hand back the short result as though the read had finished.

// internalRoot is where both this contract and the coverage check below look.
// Shared so that narrowing one narrows the other, and the coverage floors fire.
const internalRoot = ".."

// The headline.
func TestNoRowLoopAnywhereInInternalSkipsRowsErr(t *testing.T) {
	for _, p := range reportRowLoops(findRowLoops(t, internalRoot), knownUncheckedRowLoops) {
		t.Error(p)
	}
}

// The scanner has to find an unchecked loop when there is one. Every other
// assertion here is satisfied by a scanner that finds nothing, so this points
// it at a directory that definitely contains one.
func TestTheScannerFindsAnUncheckedLoopOnDisk(t *testing.T) {
	dir := t.TempDir()
	const fixture = `package p

func good(rows R) error {
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

func bad(rows R) error {
	for rows.Next() {
	}
	return nil
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got := findRowLoops(t, dir)
	if len(got) != 1 {
		t.Fatalf("検出結果が %d 件です (want 1): %+v。"+
			"走査そのものが機能していないと、この契約は「何も見つからない」で通ります", len(got), got)
	}
	if got[0].fn != "bad" || got[0].v != "rows" {
		t.Errorf("検出内容が違います: %+v", got[0])
	}
}

// And the walk must be reaching the whole tree, or the contract above is
// satisfied by finding nothing.
func TestTheInternalWalkReachesEveryPackage(t *testing.T) {
	fset := token.NewFileSet()
	pkgs := map[string]bool{}
	var loops int
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		pkgs[filepath.Dir(path)] = true
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if fs, ok := n.(*ast.ForStmt); ok && nextReceiver(fs) != "" {
				loops++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}
	for _, p := range coverageProblems(len(pkgs), loops) {
		t.Error(p)
	}
}

// coverageProblems is separated out for the same reason every other rule in
// this file is: with the real numbers far above the floors, neither comparison
// is ever reached, and a check that never fires looks exactly like one that was
// deleted.
func coverageProblems(pkgs, loops int) []string {
	var out []string
	if pkgs < 30 {
		out = append(out, fmt.Sprintf(
			"internal/ 配下のパッケージが %d 個しか見つかりません。"+
				"走査が木を降りていない可能性があります", pkgs))
	}
	if loops < 150 {
		out = append(out, fmt.Sprintf(
			"結果セットを走査するループが %d 個しか見つかりません。"+
				"ゲートが対象を見失っている可能性があります", loops))
	}
	return out
}

func TestTheCoverageFloorsActuallyFire(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pkgs, loops int
		want        int
	}{
		{"どちらも十分", 60, 400, 0},
		{"パッケージが足りない", 3, 400, 1},
		{"ループが足りない", 60, 10, 1},
		{"どちらも足りない（走査が空振り）", 0, 0, 2},
	} {
		if got := coverageProblems(tc.pkgs, tc.loops); len(got) != tc.want {
			t.Errorf("%s: %d件 (want %d): %v", tc.name, len(got), tc.want, got)
		}
	}
}
