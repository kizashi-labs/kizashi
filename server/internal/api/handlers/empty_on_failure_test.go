package handlers

import (
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 93 read endpoints answered a database failure with 200 and an empty body.
// The console renders that: zero vulnerabilities, zero open alerts, zero
// certificates expiring, zero awareness courses outstanding. For a SOC those
// screens are an answer — "there is nothing to look at" — and the answer was
// that we could not look. An empty list is the shape a lie takes when it wants
// to be reassuring.
//
// The one failure that genuinely does mean "there is nothing here" is absence:
// a table the migration has not created (42P01), or a row that is not there
// (pgx.ErrNoRows). Those keep the empty body, because a feature nobody has
// enabled really does have no rows. Everything else — the database is
// unreachable, the role lacks SELECT, the statement timed out — is a 500.
//
// That distinction is the whole point, so it is tested directly rather than
// inferred from the call sites.

func init() { gin.SetMode(gin.TestMode) }

func TestAbsenceAndFailureAreDistinguished(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"テーブルが未作成 (42P01)", &pgconn.PgError{Code: "42P01"}, 200},
		{"行が無い", pgx.ErrNoRows, 200},
		{"包まれた 42P01", errors.Join(errors.New("x"), &pgconn.PgError{Code: "42P01"}), 200},
		{"包まれた ErrNoRows", errors.Join(errors.New("x"), pgx.ErrNoRows), 200},
		{"接続不可", errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"), 500},
		{"権限不足 (42501)", &pgconn.PgError{Code: "42501"}, 500},
		{"文法エラー (42601)", &pgconn.PgError{Code: "42601"}, 500},
		{"列が無い (42703)", &pgconn.PgError{Code: "42703"}, 500},
		{"タイムアウト (57014)", &pgconn.PgError{Code: "57014"}, 500},
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		ReadFailure(c, tc.err, gin.H{"items": []any{}})
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d。"+
				"「そこに無い」と「見に行けなかった」を取り違えています",
				tc.name, w.Code, tc.want)
		}
		if tc.want == 200 && !strings.Contains(w.Body.String(), `"items"`) {
			t.Errorf("%s: 未作成のときに返すべき形が返っていません: %s", tc.name, w.Body.String())
		}
		if tc.want == 500 && strings.Contains(w.Body.String(), `"items"`) {
			t.Errorf("%s: 失敗しているのに空のリストを返しています: %s", tc.name, w.Body.String())
		}
	}
}

// ─── the call sites ──────────────────────────────────────────────────────────

// emptyBody reports whether a response body is nothing but empty collections,
// zeros, empty strings, nil and false — the shape that reads as "there is
// nothing here".
func emptyBody(e ast.Expr) bool {
	ok := true
	var walk func(ast.Expr)
	walk = func(x ast.Expr) {
		switch v := x.(type) {
		case *ast.CompositeLit:
			for _, el := range v.Elts {
				if kv, isKV := el.(*ast.KeyValueExpr); isKV {
					walk(kv.Value)
				} else {
					ok = false
				}
			}
		case *ast.BasicLit:
			switch v.Value {
			case "0", `""`, "0.0":
			default:
				ok = false
			}
		case *ast.Ident:
			switch v.Name {
			case "nil", "false":
			default:
				ok = false
			}
		case *ast.UnaryExpr:
			walk(v.X)
		default:
			ok = false
		}
	}
	walk(e)
	return ok
}

type emptySite struct {
	file string
	fn   string
	line int
	body string
}

// findEmptyOnFailure finds every `if err != nil { ... c.JSON(200, <empty>) }`.
func findEmptyOnFailure(t *testing.T, dirs ...string) []emptySite {
	t.Helper()
	var out []emptySite
	for _, dir := range dirs {
		fset := token.NewFileSet()
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
					if !ok || is.Init != nil {
						return true
					}
					bin, ok := is.Cond.(*ast.BinaryExpr)
					if !ok || bin.Op != token.NEQ {
						return true
					}
					x, xok := bin.X.(*ast.Ident)
					y, yok := bin.Y.(*ast.Ident)
					if !xok || !yok || !strings.Contains(x.Name, "err") || y.Name != "nil" {
						return true
					}
					if call, body := okJSONIn(is.Body); call != nil && emptyBody(body) {
						out = append(out, emptySite{
							file: filepath.Base(path), fn: fn.Name.Name,
							line: fset.Position(call.Pos()).Line,
							body: render(fset, body),
						})
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out
}

// okJSONIn returns the c.JSON(http.StatusOK, body) call inside a block.
func okJSONIn(b *ast.BlockStmt) (*ast.CallExpr, ast.Expr) {
	var call *ast.CallExpr
	var body ast.Expr
	ast.Inspect(b, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || call != nil || len(ce.Args) != 2 {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		if _, ok := sel.X.(*ast.Ident); !ok {
			return true
		}
		st, ok := ce.Args[0].(*ast.SelectorExpr)
		if !ok || st.Sel.Name != "StatusOK" {
			return true
		}
		call, body = ce, ce.Args[1]
		return true
	})
	return call, body
}

func render(fset *token.FileSet, n ast.Node) string {
	var b strings.Builder
	_ = format.Node(&b, fset, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// The headline: nowhere in the API answers a database failure with an empty
// body directly. It has to go through ReadFailure, which is the one place that
// decides whether the emptiness is true.
// apiDirs is shared with the coverage check below, so narrowing the walk
// narrows both and the floor there fires.
var apiDirs = []string{".", ".."}

func TestNoDatabaseFailureIsAnsweredWithAnEmptyBody(t *testing.T) {
	sites := findEmptyOnFailure(t, apiDirs...)
	for _, s := range sites {
		t.Errorf("%s:%d %s が、読み取り失敗に 200 と空の応答を返しています。\n"+
			"  %s\n"+
			"  コンソールには「該当なし」と表示されます。ReadFailure に通して\n"+
			"  ください — 未作成のテーブルと行なしだけがその形に値します。",
			s.file, s.line, s.fn, s.body)
	}
}

// The detector has to be able to find one, or the contract above is satisfied
// by a scan that sees nothing.
func TestTheEmptyBodyDetectorRecognisesTheShape(t *testing.T) {
	const src = `package p
func bad(c *ctx) {
	rows, err := q()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"items": []any{}, "total": 0})
		return
	}
	_ = rows
}
func viaHelper(c *ctx) {
	rows, err := q()
	if err != nil {
		ReadFailure(c, err, gin.H{"items": []any{}})
		return
	}
	_ = rows
}
func honest(c *ctx) {
	rows, err := q()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	_ = rows
}
func partial(c *ctx) {
	rows, err := q()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"groups": groups})
		return
	}
	_ = rows
}
func afterAWriteThatWorked(c *ctx) {
	v, err := readBack()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
		return
	}
	_ = v
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var found []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			is, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			if call, body := okJSONIn(is.Body); call != nil && emptyBody(body) {
				found = append(found, fn.Name.Name)
			}
			return true
		})
	}
	if len(found) != 1 || found[0] != "bad" {
		t.Errorf("検出結果が %v です (want [bad])。\n"+
			"  ReadFailure 経由・正直なエラー本文・部分的に埋まった応答・\n"+
			"  書き込み成功後の読み直しは、いずれも対象ではありません", found)
	}
}

// And the walk must be reaching the code, not an empty tree.
func TestTheEmptyBodyScanReachesTheHandlers(t *testing.T) {
	fset := token.NewFileSet()
	var okJSONs int
	seen := map[string]bool{}
	for _, dir := range apiDirs {
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			seen[filepath.Base(path)] = true
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				// **黙って飛ばすと、その file は走査から消えます。**
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok || len(ce.Args) != 2 {
					return true
				}
				if sel, ok := ce.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "JSON" {
					if st, ok := ce.Args[0].(*ast.SelectorExpr); ok && st.Sel.Name == "StatusOK" {
						okJSONs++
					}
				}
				return true
			})
			return nil
		})
		if walkErr != nil {
			t.Fatalf("%s を走査できません: %v", dir, walkErr)
		}
	}
	if okJSONs < 300 {
		t.Errorf("200応答が %d 個しか見つかりません。走査が届いていない可能性があります", okJSONs)
	}
	// A count alone does not prove both packages were walked: handlers has
	// enough 200 responses on its own to clear the floor while internal/api is
	// silently skipped. Name a file from each.
	for _, want := range []string{"errs.go", "router.go"} {
		if !seen[want] {
			t.Errorf("%s に到達していません。走査の範囲が狭まっています", want)
		}
	}
}

// ─── affirmative verdicts ────────────────────────────────────────────────────
//
// An empty list is one shape the lie takes. The other is a verdict.
//
// ValidatePassword read the active policy and, when it could not, answered
// {"valid": true, "violations": []}: a password accepted because the rules
// governing it were unreadable. The same shape would be a compliance check
// reporting compliant, or a health check reporting healthy. These are not
// "nothing here" — they are "yes", which is worse, because the caller acts on
// a yes.
var affirmativeVerdictFields = []string{
	"valid", "compliant", "passed", "pass", "healthy", "authorized",
	"allowed", "verified", "safe",
}

func TestNoDatabaseFailureIsAnsweredWithAYes(t *testing.T) {
	fset := token.NewFileSet()
	var problems []string

	for _, dir := range apiDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				// **黙って飛ばすと、その file は走査から消えます。**
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				is, ok := n.(*ast.IfStmt)
				if !ok || is.Init != nil {
					return true
				}
				bin, ok := is.Cond.(*ast.BinaryExpr)
				if !ok || bin.Op != token.NEQ {
					return true
				}
				x, xok := bin.X.(*ast.Ident)
				y, yok := bin.Y.(*ast.Ident)
				if !xok || !yok || !strings.Contains(x.Name, "err") || y.Name != "nil" {
					return true
				}
				call, body := okJSONIn(is.Body)
				if call == nil {
					return true
				}
				if field := affirmativeIn(body); field != "" {
					problems = append(problems, fmt.Sprintf(
						"%s:%d が、読み取り失敗に 200 と %q: true を返しています。\n"+
							"  %s\n"+
							"  「該当なし」ではなく「はい」です。呼び出し側はその「はい」で動きます。",
						filepath.Base(path), fset.Position(call.Pos()).Line, field, render(fset, body)))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// affirmativeIn returns the first verdict field set to true in a response body.
func affirmativeIn(e ast.Expr) string {
	found := ""
	ast.Inspect(e, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok || found != "" {
			return true
		}
		key, ok := kv.Key.(*ast.BasicLit)
		if !ok || key.Kind != token.STRING {
			return true
		}
		val, ok := kv.Value.(*ast.Ident)
		if !ok || val.Name != "true" {
			return true
		}
		name := strings.Trim(key.Value, `"`)
		for _, f := range affirmativeVerdictFields {
			if name == f {
				found = name
			}
		}
		return true
	})
	return found
}

// And it has to be able to fire.
func TestTheAffirmativeVerdictDetectorWorks(t *testing.T) {
	parse := func(src string) ast.Expr {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nvar _ = "+src, 0)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		return f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0]
	}
	for _, tc := range []struct{ src, want string }{
		{`gin.H{"valid": true, "violations": []string{}}`, "valid"},
		{`gin.H{"compliant": true}`, "compliant"},
		{`gin.H{"healthy": true, "detail": ""}`, "healthy"},
		{`gin.H{"valid": false}`, ""},
		{`gin.H{"items": []any{}}`, ""},
		{`gin.H{"is_default": true}`, ""},
		{`gin.H{"ok": false, "error": e}`, ""},
	} {
		if got := affirmativeIn(parse(tc.src)); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.src, got, tc.want)
		}
	}
}
