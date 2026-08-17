package remediation

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The exclusion list names the hosts auto-remediation must never touch: domain
// controllers, production databases, the jump box the responder is sitting on.
// The engine's actions include isolating a host from the network.
//
// LoadExclusionsFromDB used to run its table-existence probe through
// `_ = e.pool.QueryRow(...)`. A database that was unreachable, a role without
// permission on information_schema, a cancelled startup context — any of those
// left `exists` false, which the function read as "the migration has not run",
// so it returned nil. Success. The engine then ran with an empty exclusion
// list, and an empty list and an unread list are the same value with opposite
// meanings: "nothing is excluded" versus "we could not find out what is
// excluded". The caller at cmd/api/main.go only logs a warning either way, so
// there was no second chance to notice.
//
// Two further paths did the same quietly: rows.Err() was never checked, so an
// iteration that failed halfway left a truncated list that looked complete, and
// an unscannable row was dropped with a warning, putting exactly one protected
// host back in scope.
//
// The fix is to fail closed. A load that did not produce an answer marks the
// list unreadable, and IsExcluded then reports every host as excluded. Skipping
// remediation is recoverable — the analyst acts by hand. Isolating a domain
// controller during an incident, because the exemption that named it could not
// be read, is not.

// ─── The headline ────────────────────────────────────────────────────────────

// deadPool is a pool whose every query fails: a parseable DSN pointing at a
// port nothing listens on. pgxpool connects lazily, so construction succeeds
// and the failure arrives at the first query — which is the real shape of a
// database that is down when the server starts.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody@127.0.0.1:1/nothing?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatalf("dead pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAnUnreadableExclusionListStopsAutoRemediation(t *testing.T) {
	e := NewEngine(deadPool(t), nil)
	e.AddRule(&RemediationRule{
		ID:      "isolate",
		Name:    "Isolate on critical",
		Enabled: true,
		Trigger: RuleTrigger{MinSeverity: 1},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.LoadExclusionsFromDB(ctx); err == nil {
		t.Fatal("除外リストを読めなかったのに成功を返しています。" +
			"呼び出し側は空のリストを「除外なし」として受け取ります")
	}

	for _, host := range []string{"dc-primary", "prod-db-01", "some-random-laptop", ""} {
		if !e.IsExcluded(host) {
			t.Errorf("除外リストが読めていないのに %q を自動修復の対象にしています。"+
				"このホストが除外指定されていたかどうかは分かっていません", host)
		}
	}

	logs := e.TriggerOnAlert(ctx, "alert-1", "agent-1", "dc-primary", 10, nil)
	if len(logs) != 0 {
		t.Errorf("除外リストが読めていない状態でルールを実行しました: %d件。"+
			"インシデント中にドメインコントローラを隔離しうる経路です", len(logs))
	}
}

// The empty hostname deserves its own assertion. IsExcluded has a deliberate
// "empty hostname never matches" branch — TriggerOnAlert's contract lets the
// caller pass "" when the hostname is unknown — and if that branch ran first,
// an alert with no hostname would sail through the fail-closed check.
func TestAnUnknownHostnameIsAlsoWithheldWhenTheListIsUnreadable(t *testing.T) {
	e := NewEngine(nil, nil)
	e.markExclusionsUnreadable()
	if !e.IsExcluded("") {
		t.Error("除外リストが読めていないのに、ホスト名不明のアラートだけ" +
			"自動修復の対象になっています。どのホストか分からない以上、" +
			"除外指定の有無も分かりません")
	}
}

// ─── The narrowing, which is the part that is easy to get wrong ──────────────

// The flag means "a load was attempted and failed", not "no load has happened".
// An engine with no database, or one whose exclusions were added in memory by
// the API handler, knows its list perfectly well. Gating on "has loaded" would
// disable auto-remediation for every construction path that never calls the
// loader — trading a silent wrong answer for a silent no answer.
func TestAnEngineThatNeverLoadedStillRemediates(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{
		ID: "r1", Name: "Isolate", Enabled: true,
		Trigger: RuleTrigger{MinSeverity: 1},
	})
	e.AddExclusion(RemediationExclusion{HostnamePattern: "dc-*"})

	if e.IsExcluded("web-01") {
		t.Error("DBを持たないエンジンで除外対象でないホストが除外されています。" +
			"「読み込んでいない」を「読めなかった」と同じ扱いにすると、" +
			"自動修復そのものが黙って止まります")
	}
	if !e.IsExcluded("dc-01") {
		t.Error("メモリ上の除外指定が効いていません")
	}
	if logs := e.TriggerOnAlert(context.Background(), "a", "ag", "web-01", 9, nil); len(logs) == 0 {
		t.Error("除外対象でないホストでルールが実行されませんでした")
	}
}

// A pool that is nil is not a failure either. LoadExclusionsFromDB returns
// early, and the engine must stay usable.
func TestLoadingWithNoPoolIsNotAFailure(t *testing.T) {
	e := NewEngine(nil, nil)
	if err := e.LoadExclusionsFromDB(context.Background()); err != nil {
		t.Fatalf("pool が nil のとき LoadExclusionsFromDB はエラーを返しません: %v", err)
	}
	if e.IsExcluded("anything") {
		t.Error("pool が nil なだけで自動修復が止まっています")
	}
}

// ─── The recovery ────────────────────────────────────────────────────────────

// A load that produced an answer clears the flag. "The table does not exist" is
// as definite an answer as a row set, so both success paths must clear it —
// otherwise a deployment where migration 245 has not run yet would be stuck
// failing closed forever.
func TestAnAnswerClearsTheUnreadableFlag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		loaded []RemediationExclusion
	}{
		{"読み込めた除外リスト", []RemediationExclusion{{HostnamePattern: "dc-*"}}},
		{"テーブルが無い（除外ゼロ件）", nil},
	} {
		e := NewEngine(nil, nil)
		e.markExclusionsUnreadable()
		if !e.IsExcluded("web-01") {
			t.Fatalf("%s: 前提が崩れています", tc.name)
		}

		e.applyExclusions(tc.loaded)

		if e.IsExcluded("web-01") {
			t.Errorf("%s: 読み込みに成功した後も自動修復が止まったままです", tc.name)
		}
	}

	// And a successful load still installs the list it read.
	e := NewEngine(nil, nil)
	e.applyExclusions([]RemediationExclusion{{HostnamePattern: "dc-*"}})
	if !e.IsExcluded("dc-01") {
		t.Error("読み込んだ除外指定が効いていません")
	}
	if e.IsExcluded("web-01") {
		t.Error("読み込んだ除外指定が無関係なホストにマッチしています")
	}
}

// ─── The loader's shape ──────────────────────────────────────────────────────
//
// The behavioural tests above reach the existence probe. The Query, Scan and
// rows.Err failures need a database that fails in a specific way partway
// through, which no fixture here can arrange, so they are pinned structurally
// instead: every way out of the loader that reports failure must first record
// that the list is unreadable. A path that returns an error without recording
// it is the original bug wearing an error return — the caller logs a warning
// and the engine carries on with a list it did not read.

func loaderBody(t *testing.T) (*token.FileSet, *ast.FuncDecl, string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "engine.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse engine.go: %v", err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "LoadExclusionsFromDB" {
			return fset, fn, "LoadExclusionsFromDB"
		}
	}
	t.Fatal("LoadExclusionsFromDB が見つかりません")
	return nil, nil, ""
}

// callsMarkUnreadable reports whether stmt is `e.markExclusionsUnreadable()`.
func callsMarkUnreadable(stmt ast.Stmt) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "markExclusionsUnreadable"
}

// returnsAnError reports whether the return statement yields a non-nil error.
func returnsAnError(ret *ast.ReturnStmt) bool {
	for _, r := range ret.Results {
		if id, ok := r.(*ast.Ident); ok && id.Name == "nil" {
			continue
		}
		return true
	}
	return false
}

func TestEveryFailurePathInTheLoaderFailsClosed(t *testing.T) {
	fset, fn, name := loaderBody(t)

	var checked int
	// Walk every block in the function and look at each `return <error>` in the
	// context of the statements around it.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch b := n.(type) {
		case *ast.BlockStmt:
			list = b.List
		case *ast.CaseClause:
			list = b.Body
		default:
			return true
		}
		for i, stmt := range list {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || !returnsAnError(ret) {
				continue
			}
			checked++
			guarded := false
			for j := 0; j < i; j++ {
				if callsMarkUnreadable(list[j]) {
					guarded = true
				}
			}
			if !guarded {
				t.Errorf("%s:%d: %s がエラーを返す前に markExclusionsUnreadable() を"+
					"呼んでいません。呼び出し側は警告を出すだけなので、"+
					"読めなかった除外リストのままエンジンが動き続けます",
					name, fset.Position(ret.Pos()).Line, name)
			}
		}
		return true
	})

	if checked < 4 {
		t.Errorf("%s のエラー経路が %d 本しか見つかりません。"+
			"経路が減ったのなら、このゲートも合わせて見直してください", name, checked)
	}
}

// rows.Err() is the failure with no symptom at all: the loop simply ends early
// and the short list is installed as if it were the whole thing.
func TestTheLoaderChecksRowsErr(t *testing.T) {
	_, fn, name := loaderBody(t)
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Err" {
			found = true
		}
		return true
	})
	if !found {
		t.Errorf("%s が rows.Err() を見ていません。"+
			"途中で失敗した反復は切り詰められた除外リストを残し、"+
			"完全なものとして採用されます", name)
	}
}

// And the probe whose discarded error started all of this must not go back to
// being discarded. `exists` defaulting to false is indistinguishable from "the
// migration has not run", which is the one answer that is treated as success.
func TestTheExistenceProbeErrorIsNotDiscarded(t *testing.T) {
	_, fn, _ := loaderBody(t)

	var offenders int
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		blank := false
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
				blank = true
			}
		}
		if !blank {
			return true
		}
		for _, rhs := range assign.Rhs {
			if strings.Contains(exprText(rhs), "QueryRow") || strings.Contains(exprText(rhs), ".Scan(") {
				offenders++
			}
		}
		return true
	})
	if offenders > 0 {
		t.Errorf("LoadExclusionsFromDB がクエリのエラーを `_` に捨てています (%d箇所)。"+
			"存在確認が失敗すると exists は false のままで、"+
			"「マイグレーション未適用」と同じ成功扱いになります", offenders)
	}
}

// exprText renders an expression's selector chain, enough to spot QueryRow/Scan
// without pulling in a printer.
func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CallExpr:
		return exprText(x.Fun) + "("
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}
