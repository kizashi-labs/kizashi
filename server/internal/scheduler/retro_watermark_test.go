package scheduler

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Most of what a scheduler loses to a truncated read comes back on the next
// tick: an alert not raised this minute is raised the next, a baseline not
// rebuilt is rebuilt an hour later. Under-action on a periodic job is a delay.
//
// Three places in this package are the exception.
//
// The two retro hunters each keep a watermark recording how far back they have
// already searched, so the next pass starts there instead of re-reading all of
// history. Advancing it is a claim: this range has been checked. Advance it
// after a scan that stopped early and the unscanned part is marked checked
// forever — for those rules and those IOCs, history is never looked at again.
// Nothing reports it, because a result set that broke halfway looks exactly
// like one that found nothing.
//
// The realtime correlator replaces its whole rule set on every reload. Install
// a truncated one and detection quietly narrows, with a rule count in the log
// that reads like any other reload.
//
// All three are the difference between "we will catch it next time" and "we
// will never catch it". Not advancing, and not installing, costs a repeated
// read — cheap, and self-correcting.
//
// These run against tables and volumes no fixture here can arrange, so the
// ordering is pinned structurally: the guard must come before the commit.

// guard is one `if ....Err()` or `if !complete` check, with whether it leaves
// the function.
type guard struct {
	pos     token.Pos
	returns bool
}

// everyCommitIsGuarded reports whether each commit has a guard that leaves the
// function somewhere between it and the previous commit.
//
// Per-commit rather than "somewhere before the last one", because a function
// with two commits — hunt() advances the watermark both on the no-new-IOCs
// early return and at the end — would otherwise let one guard cover for both.
// Drop the second and the first still sits before the last commit, so the rule
// would pass while the dangerous path was unguarded. That is exactly the
// mutation that survived the first version of this test.
//
// Both halves of the guard matter, and neither is exercised by the healthy
// code: one that does not return lets execution fall through to the commit, one
// that sits after the commit is too late.
func everyCommitIsGuarded(guards []guard, commits []token.Pos) bool {
	sorted := append([]token.Pos(nil), commits...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	prev := token.Pos(0)
	for _, c := range sorted {
		found := false
		for _, g := range guards {
			if g.pos > prev && g.pos < c && g.returns {
				found = true
			}
		}
		if !found {
			return false
		}
		prev = c
	}
	return true
}

func TestTheGuardOrderingRuleActuallyFires(t *testing.T) {
	for _, tc := range []struct {
		name    string
		guards  []guard
		commits []token.Pos
		want    bool
	}{
		{"手前で return する", []guard{{50, true}}, []token.Pos{100}, true},
		{"手前にあるが return しない", []guard{{50, false}}, []token.Pos{100}, false},
		{"return するが commit より後ろ", []guard{{150, true}}, []token.Pos{100}, false},
		{"ガードが無い", nil, []token.Pos{100}, false},
		{"複数あり、手前の1つが return する",
			[]guard{{40, false}, {60, true}, {150, true}}, []token.Pos{100}, true},
		{"commit が2つ、それぞれにガードあり",
			[]guard{{50, true}, {150, true}}, []token.Pos{100, 200}, true},
		{"commit が2つ、2つ目のガードが無い",
			[]guard{{50, true}}, []token.Pos{100, 200}, false},
		{"commit が2つ、1つ目のガードが無い",
			[]guard{{150, true}}, []token.Pos{100, 200}, false},
	} {
		if got := everyCommitIsGuarded(tc.guards, tc.commits); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// parseFn returns the declaration of fn in file, plus its source text.
func parseFn(t *testing.T, file, fn string) (*ast.FuncDecl, string) {
	t.Helper()
	fset := token.NewFileSet()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		return fd, string(src[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset])
	}
	t.Fatalf("%s に %s が見つかりません", file, fn)
	return nil, ""
}

// callsNamed returns the positions of every call whose selector is name.
func callsNamed(n ast.Node, name string) []token.Pos {
	var out []token.Pos
	if n == nil {
		return nil
	}
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			out = append(out, call.Pos())
		}
		return true
	})
	return out
}

func leaves(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if _, ok := x.(*ast.ReturnStmt); ok {
			found = true
		}
		return true
	})
	return found
}

// guardsIn collects every if-statement whose condition or init mentions Err()
// or the identifier `complete`.
func guardsIn(body *ast.BlockStmt) []guard {
	var out []guard
	ast.Inspect(body, func(x ast.Node) bool {
		is, ok := x.(*ast.IfStmt)
		if !ok {
			return true
		}
		relevant := len(callsNamed(is.Init, "Err")) > 0 || len(callsNamed(is.Cond, "Err")) > 0
		if !relevant {
			ast.Inspect(is.Cond, func(y ast.Node) bool {
				if id, ok := y.(*ast.Ident); ok && id.Name == "complete" {
					relevant = true
				}
				return true
			})
		}
		if relevant {
			out = append(out, guard{is.Pos(), leaves(is.Body)})
		}
		return true
	})
	return out
}

// The rule hunter advances its watermark inline, at the end of hunt().
func TestTheRuleHunterDoesNotAdvancePastAHistoryItCouldNotRead(t *testing.T) {
	fn, _ := parseFn(t, "retro_rule_hunter.go", "hunt")

	var advances []token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, a := range call.Args {
			if lit, ok := a.(*ast.BasicLit); ok &&
				strings.Contains(lit.Value, "UPDATE retro_rule_state") {
				advances = append(advances, call.Pos())
			}
		}
		return true
	})
	if len(advances) == 0 {
		t.Fatal("watermark を進める UPDATE が見つかりません。" +
			"移動したのならこのゲートも追随させてください")
	}

	// The scan of history must abandon the pass. The scan of new rules need not:
	// that query is ORDER BY created_at ascending, so truncation only ever drops
	// the newest rules and maxTS stays behind them — the dropped ones are still
	// past the watermark next time.
	if !everyCommitIsGuarded(guardsIn(fn.Body), advances) {
		t.Error("履歴の走査が途中で終わっても watermark を進めています。\n" +
			"  そのルール群にとって、読めなかった区間は永久に「照合済み」になります。\n" +
			"  進めなければ次回やり直せます")
	}
}

// The IOC hunter threads completeness up to hunt() instead, because its scan is
// spread over eleven calls to huntField.
func TestTheIOCHunterDoesNotAdvancePastAHistoryItCouldNotRead(t *testing.T) {
	fn, _ := parseFn(t, "retro_ioc_hunter.go", "hunt")

	advances := callsNamed(fn.Body, "advanceWatermark")
	if len(advances) == 0 {
		t.Fatal("advanceWatermark の呼び出しが見つかりません")
	}
	if !everyCommitIsGuarded(guardsIn(fn.Body), advances) {
		t.Error("読み切れなかったパスでも watermark を進めています。\n" +
			"  そのIOCにとって、走査できなかった区間は永久に「照合済み」になります")
	}

	// And the loaders have to be able to report incompleteness at all.
	for _, name := range []string{"loadNewIOCs", "huntField"} {
		f, src := parseFn(t, "retro_ioc_hunter.go", name)
		if f.Type.Results == nil {
			t.Errorf("%s に戻り値がありません", name)
			continue
		}
		head := src
		if i := strings.Index(src, "{"); i > 0 {
			head = src[:i]
		}
		if !strings.Contains(head, "complete bool") {
			t.Errorf("%s が読み取りの完了状態を返していません。"+
				"呼び出し側は不完全なパスを完全なものと区別できません", name)
		}
	}
}

// The correlator's commit is an assignment rather than a call.
func TestTheCorrelatorDoesNotInstallARuleSetItCouldNotRead(t *testing.T) {
	fn, _ := parseFn(t, "realtime_correlator.go", "loadRules")

	var installs []token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "rules" {
				installs = append(installs, as.Pos())
			}
		}
		return true
	})
	if len(installs) == 0 {
		t.Fatal("ルール集合の入れ替えが見つかりません。" +
			"移動したのならこのゲートも追随させてください")
	}
	if !everyCommitIsGuarded(guardsIn(fn.Body), installs) {
		t.Error("読み切れなかったルール集合をそのまま入れ替えています。\n" +
			"  検知が黙って狭まり、ログには他の再読み込みと同じ件数が出ます。\n" +
			"  入れ替えなければ前回のルールが残り、次回やり直せます")
	}
}

// ─── the state table ─────────────────────────────────────────────────────────
//
// ensureState created retro_rule_state with both Exec errors discarded. The
// failure had no symptom of its own: hunt()'s SELECT then failed, hunt() read
// that as "state missing — skip", and the retro rule hunter did nothing at all
// on every tick, for the lifetime of the process, silently.
//
// Migration 382 declares the table, so a failure here now means something else
// — no permission, no database — and that is worth saying out loud.

func TestPreparingTheStateReportsItsFailure(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody@127.0.0.1:1/nothing?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatalf("dead pool: %v", err)
	}
	t.Cleanup(pool.Close)

	h := &RetroRuleHunter{pool: pool}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = h.ensureState(ctx)
	if err == nil {
		t.Fatal("状態テーブルを用意できないのに成功を返しています。" +
			"この後 hunt() の SELECT が失敗し、「状態が無い」として毎回黙って" +
			"見送られます — 遡及ハントは一度も動きません")
	}
	// どちらの手順で落ちたかが分かること。2つの Exec のエラーが同じ扱いだと、
	// 片方だけ捨てても振る舞いが変わらず、テストが素通りします。
	if !strings.Contains(err.Error(), "状態テーブル") {
		t.Errorf("最初に失敗するのは CREATE TABLE なのに、そう報告されていません: %v", err)
	}
}

// 2つ目の Exec のエラーも、それ自体で報告されること。
func TestPreparingTheStateRowReportsItsOwnFailure(t *testing.T) {
	_, src := parseFn(t, "retro_rule_hunter.go", "ensureState")
	for _, want := range []string{"状態テーブルを用意できませんでした", "状態行を用意できませんでした"} {
		if !strings.Contains(src, want) {
			t.Errorf("ensureState が %q を報告しません。2つの手順の失敗が"+
				"見分けられないと、片方を捨てても誰も気づきません", want)
		}
	}
}

// And hunt() must not carry on past it. Reaching the watermark logic with no
// state is how the silence started.
func TestHuntStopsWhenTheStateIsNotThere(t *testing.T) {
	fn, _ := parseFn(t, "retro_rule_hunter.go", "hunt")

	var guarded, called bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if len(callsNamed(is.Init, "ensureState")) == 0 &&
			len(callsNamed(is.Cond, "ensureState")) == 0 {
			return true
		}
		called = true
		if leaves(is.Body) {
			guarded = true
		}
		return true
	})
	if !called {
		t.Fatal("hunt() が ensureState の結果を条件にしていません。" +
			"戻り値を捨てると、状態が無いまま先へ進みます")
	}
	if !guarded {
		t.Error("状態を用意できなくても hunt() が続行しています")
	}
}
