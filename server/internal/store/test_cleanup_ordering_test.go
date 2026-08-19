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

// A test that opens a pool with `defer pool.Close()` and then registers
// `t.Cleanup(func(){ pool.Exec(...) })` never cleans up.
//
// t.Cleanup functions run after the test function returns — after its deferred
// calls. By the time the cleanup runs the pool is closed, so every statement it
// issues fails, and these cleanups discard their errors into `_, _ =`. Measured
// directly: the cleanup's DELETE reported `rows=0 err=closed pool`, the row
// survived, and the test passed.
//
// The cost is invisible on CI, which gets a fresh database per run, and
// compounds on any long-lived one: after N runs the table holds N copies of the
// fixture, and the first unique constraint they hit turns into a failure that
// looks like a product bug. That is exactly what happened here —
// compliance_alerter_test.go accumulated 'compl-alert-host' agents until its
// own seed failed with
// `duplicate key value violates unique constraint "uq_hardening_baselines_name"`.
//
// Unlike some ordering faults this one is reliably visible in the syntax: the
// deferred Close and the cleanup that uses the same identifier are in one
// function body. So it is worth a static gate.

// cleanupOrderingViolation is one test function that closes a resource with
// defer while a t.Cleanup still needs it.
type cleanupOrderingViolation struct {
	file     string
	line     int
	function string
	resource string
}

func (v cleanupOrderingViolation) String() string {
	return fmt.Sprintf("%s:%d %s: `defer %s.Close()` runs before the t.Cleanup that uses %s",
		v.file, v.line, v.function, v.resource, v.resource)
}

// deferredCloses returns the receiver names of `defer X.Close()` statements
// directly in this function body.
func deferredCloses(fn *ast.FuncDecl) map[string]ast.Node {
	out := map[string]ast.Node{}
	ast.Inspect(fn, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		sel, ok := d.Call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Close" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			out[ident.Name] = d
		}
		return true
	})
	return out
}

// cleanupBodiesReferencing reports the t.Cleanup calls in fn whose argument
// mentions one of the given identifiers, and which one.
func cleanupBodiesReferencing(fn *ast.FuncDecl, names map[string]ast.Node) []struct {
	node ast.Node
	name string
} {
	var out []struct {
		node ast.Node
		name string
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cleanup" {
			return true
		}
		if len(call.Args) != 1 {
			return true
		}
		// t.Cleanup(pool.Close) is deliberately NOT exempted here. On its own it
		// cannot match, because a function using that form has no deferred close
		// for `names` to contain. It can only match when the same function ALSO
		// defers the close — and that combination is a genuine fault worth
		// reporting, since the defer still runs first and defeats the cleanup.
		// An exemption would have been dead code that suppressed a true positive
		// in the one case it could fire.
		ast.Inspect(call.Args[0], func(inner ast.Node) bool {
			id, ok := inner.(*ast.Ident)
			if !ok {
				return true
			}
			if _, tracked := names[id.Name]; tracked {
				out = append(out, struct {
					node ast.Node
					name string
				}{call, id.Name})
				return false
			}
			return true
		})
		return true
	})
	return out
}

// scanCleanupOrdering walks root for _test.go files and returns the violations
// plus the number of function bodies it examined.
//
// It takes root as a parameter so the reporting path can be exercised against a
// crafted fixture. Otherwise it is only ever run over a tree with no violations
// left in it, and nothing distinguishes "found none" from "reports none" — a
// mutation that collected violations and then dropped them survived until this
// was split out.
func scanCleanupOrdering(root string) ([]cleanupOrderingViolation, int, error) {
	fset := token.NewFileSet()
	var violations []cleanupOrderingViolation
	scanned := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel, _ := filepath.Rel(root, path)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			scanned++
			closes := deferredCloses(fn)
			if len(closes) == 0 {
				continue
			}
			for _, h := range cleanupBodiesReferencing(fn, closes) {
				violations = append(violations, cleanupOrderingViolation{
					file:     rel,
					line:     fset.Position(h.node.Pos()).Line,
					function: fn.Name.Name,
					resource: h.name,
				})
			}
		}
		return nil
	})
	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	return violations, scanned, err
}

// TestNoTestClosesAResourceItsCleanupStillNeeds is the gate.
func TestNoTestClosesAResourceItsCleanupStillNeeds(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected the module root at %s: %v", root, err)
	}

	violations, scanned, err := scanCleanupOrdering(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Self-check: a walk that parsed nothing would report no violations for the
	// wrong reason.
	if scanned < 500 {
		t.Fatalf("only %d test-file functions parsed — the sweep has drifted and "+
			"this gate is measuring almost nothing", scanned)
	}

	for _, v := range violations {
		t.Errorf("%s.\nCleanups run after the function's deferred calls, so this one "+
			"executes against a closed resource and every statement in it fails — "+
			"silently, because these cleanups discard their errors. Register the "+
			"close with t.Cleanup instead: cleanups are LIFO, so a close registered "+
			"first runs last.", v)
	}
}

// TestTheSweepReportsWhatItFinds drives the whole path — walk, detect, format —
// over a directory containing one deliberately broken test, so the reporting
// half is exercised even though the repository itself is clean.
func TestTheSweepReportsWhatItFinds(t *testing.T) {
	dir := t.TempDir()
	const bad = `package p

import "testing"

func TestBrokenCleanup(t *testing.T) {
	pool := open()
	defer pool.Close()
	t.Cleanup(func() { pool.Exec("DELETE FROM x") })
}

func TestFine(t *testing.T) {
	pool := open()
	t.Cleanup(pool.Close)
	t.Cleanup(func() { pool.Exec("DELETE FROM x") })
}
`
	if err := os.WriteFile(filepath.Join(dir, "sample_test.go"), []byte(bad), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	violations, scanned, err := scanCleanupOrdering(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned != 2 {
		t.Errorf("scanned %d functions, want 2", scanned)
	}
	if len(violations) != 1 {
		t.Fatalf("found %d violation(s), want 1: %v", len(violations), violations)
	}
	v := violations[0]
	if v.function != "TestBrokenCleanup" {
		t.Errorf("function = %q, want TestBrokenCleanup", v.function)
	}
	if v.resource != "pool" {
		t.Errorf("resource = %q, want pool", v.resource)
	}
	if !strings.Contains(v.String(), "sample_test.go") || !strings.Contains(v.String(), "pool") {
		t.Errorf("the message does not locate the problem: %s", v.String())
	}
}

// TestTheCleanupOrderingDetectorRecognisesBothForms pins the two shapes the
// gate has to tell apart, so a regression in the matcher shows up here rather
// than as a quietly empty sweep.
func TestTheCleanupOrderingDetectorRecognisesBothForms(t *testing.T) {
	const src = `package p

import "testing"

func TestBad(t *testing.T) {
	pool := open()
	defer pool.Close()
	t.Cleanup(func() { pool.Exec("DELETE") })
}

func TestGood(t *testing.T) {
	pool := open()
	t.Cleanup(pool.Close)
	t.Cleanup(func() { pool.Exec("DELETE") })
}

func TestAlsoFine(t *testing.T) {
	pool := open()
	defer pool.Close()
	other := open()
	t.Cleanup(func() { other.Exec("DELETE") })
}

func TestBothForms(t *testing.T) {
	pool := open()
	defer pool.Close()
	t.Cleanup(pool.Close)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x_test.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		got[fn.Name.Name] = len(cleanupBodiesReferencing(fn, deferredCloses(fn)))
	}

	for name, want := range map[string]int{
		"TestBad":      1, // deferred close + a cleanup that uses it
		"TestGood":     0, // t.Cleanup(pool.Close) alone is the correct form
		"TestAlsoFine": 0, // the cleanup uses a different resource
		// Both forms at once: the defer still runs first and defeats the cleanup,
		// so this is a real fault and has to be reported rather than exempted.
		"TestBothForms": 1,
	} {
		if got[name] != want {
			t.Errorf("%s: detector found %d violation(s), want %d", name, got[name], want)
		}
	}
}
