package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoSilentRowScanTruncation guards a class of silent data loss that cost a
// full day of misdiagnosis on 2026-08-03.
//
// The shape is this:
//
//	for rows.Next() {
//	    if err := rows.Scan(...); err != nil {
//	        continue          // ← reads as "skip this row"
//	    }
//	    out = append(out, x)
//	}
//	return out, nil           // ← rows.Err() never consulted
//
// pgx v5 marks a Rows fatal and CLOSES it when Scan fails. So the `continue`
// does not skip one row — the next Next() returns false and every remaining row
// is dropped. Callers that also skip rows.Err() then return a truncated slice
// with a nil error, and list endpoints that take their count from a separate
// COUNT(*) keep reporting the full total.
//
// Live consequence: GET /api/v1/alerts answered `total: 56, per_page: 100,
// has_more: false` and returned 18 rows. One alert with agent_id NULL (an MDM
// device alert, no endpoint behind it) failed to scan into StoredAlert's
// non-pointer string fields, and the 38 older alerts behind it vanished from the
// API while sitting untouched in the table. An ATT&CK detection-rate measurement
// read 13.6% when the product had actually raised 58 correctly-attributed alerts.
// In the SOC console the same bug hides every alert older than the first
// NULL-agent one, with nothing to indicate anything is missing.
//
// What this test requires is the cheap half of the fix: whenever a Scan error is
// swallowed, rows.Err() MUST be checked before returning, so a fatal scan surfaces
// as an error instead of a short list. (Fixing the NULLs themselves — COALESCE in
// SQL or pointer scan targets — is per-query work; this guard makes the failure
// loud either way.)
//
// Scope: the whole server module. 120 violations across 68 files were measured
// tree-wide on 2026-08-04 and swept in three passes (store → api → scheduler →
// the remaining 22 packages). Walking the module root rather than a list of
// cleaned-up directories is deliberate: a new package cannot quietly reintroduce
// the pattern by virtue of not being on a list.
//
// That first sweep was incomplete, and this test is the reason it looked complete:
// it only recognised the `if err != nil { continue }` spelling. A further 71 sites
// across 30 files wrote the same bug as `if rows.Scan(...) == nil { … }` and were
// reported clean. Widening the detector (see swallowedScanError) found them; the
// lesson is that a guard's blind spot reads exactly like an absence of violations,
// so when adding a shape here, re-derive the count from the tree rather than
// trusting the previous green run.
func TestNoSilentRowScanTruncation(t *testing.T) {
	roots := []string{"../.."} // server/ — internal/, cmd/, everything below

	fset := token.NewFileSet()
	var offenders []string
	var unparsed []string

	walk := func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// 読めなかったファイルを黙って飛ばさない。**走査から消えた file は
			// 「違反なし」と区別が付かず、ゲートが自分の盲点で緑を返す。**
			unparsed = append(unparsed, path+": "+perr.Error())
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				return true
			}
			ast.Inspect(fd.Body, func(m ast.Node) bool {
				loop, ok := m.(*ast.ForStmt)
				if !ok || loop.Cond == nil || loop.Body == nil {
					return true
				}
				recv, ok := rowsReceiverOfNextLoop(loop)
				if !ok {
					return true
				}
				swallowLine, swallows := swallowedScanError(loop, recv, fset)
				if !swallows {
					return true
				}
				if checksRowsErr(fd.Body, recv) {
					return true
				}
				offenders = append(offenders,
					fset.Position(loop.Pos()).String()+" "+fd.Name.Name+
						" (Scan エラーの握り潰しが "+swallowLine+" 行目)")
				return true
			})
			return true
		})
		return nil
	}
	for _, root := range roots {
		if err := filepath.Walk(root, walk); err != nil {
			t.Fatalf("%s の走査に失敗しました: %v", root, err)
		}
	}

	// 読めなかったファイルは違反の有無を判定できていない。**黙って飛ばすと、
	// このゲート自身が「違反なし」を返す**（走査から消えたことは緑と区別が
	// 付かない）。
	for _, u := range unparsed {
		t.Errorf("走査できなかったファイルがあります。違反の有無を判定できていません: %s", u)
	}

	if len(offenders) > 0 {
		t.Errorf(`Scan エラーを continue で握り潰しながら rows.Err() を確認していない箇所が %d 件あります:

%s

pgx v5 は Scan 失敗時に Rows を fatal 化して閉じるため、continue は「その行を飛ばす」
のではなく「以降の全行を捨てる」動作になります。呼び出し元には nil エラーで短い一覧が
返り、件数を別クエリの COUNT(*) から取っている一覧APIは総数だけ正しく答え続けます。

ループの後に以下を入れてください:

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("<対象> の走査: %%w", err)
    }`, len(offenders), strings.Join(offenders, "\n"))
	}
}

// rowsReceiverOfNextLoop returns the receiver name of a `for x.Next()` loop.
func rowsReceiverOfNextLoop(loop *ast.ForStmt) (string, bool) {
	call, ok := loop.Cond.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Next" {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// swallowedScanError reports whether the loop calls recv.Scan and discards the
// error. Two shapes count, because they lose data identically:
//
//	if err := rows.Scan(...); err != nil {   //  (a) the explicit one
//	    continue
//	}
//
//	if rows.Scan(...) == nil {               //  (b) the inline one
//	    out = append(out, x)                 //      "append only on success"
//	}
//
// (b) reads as ordinary defensive code and was missed by the first version of
// this guard — 50 sites across 27 files survived the 2026-08-04 sweep because of
// it. There is no `continue` to notice, but the effect is the same and slightly
// worse: pgx has already closed the Rows by the time the condition is evaluated,
// so the next Next() returns false and every remaining row is dropped. What the
// caller gets is a short list, no error, and no branch that ever executed to hint
// at it.
func swallowedScanError(loop *ast.ForStmt, recv string, fset *token.FileSet) (string, bool) {
	scans, line := false, ""
	ast.Inspect(loop.Body, func(b ast.Node) bool {
		if c, ok := b.(*ast.CallExpr); ok {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Scan" {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == recv {
					scans = true
				}
			}
		}
		ifs, ok := b.(*ast.IfStmt)
		if !ok || ifs.Cond == nil {
			return true
		}
		bin, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.NEQ && bin.Op != token.EQL) {
			return true
		}

		// (b): the Scan call is the comparison operand itself.
		if isScanCallOn(bin.X, recv) || isScanCallOn(bin.Y, recv) {
			line = fset.Position(ifs.Pos()).String()
			return true
		}

		// (a): `if err != nil { continue }` over a separately-assigned Scan error.
		if ifs.Body == nil || len(ifs.Body.List) != 1 || bin.Op != token.NEQ {
			return true
		}
		br, ok := ifs.Body.List[0].(*ast.BranchStmt)
		if !ok || br.Tok != token.CONTINUE {
			return true
		}
		x, ok := bin.X.(*ast.Ident)
		if !ok || !strings.Contains(strings.ToLower(x.Name), "err") {
			return true
		}
		line = fset.Position(ifs.Pos()).String()
		return true
	})
	return line, scans && line != ""
}

// isScanCallOn reports whether e is a call to recv.Scan(...).
func isScanCallOn(e ast.Expr, recv string) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	s, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != "Scan" {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == recv
}

// checksRowsErr reports whether the failure is surfaced for recv — either by
// calling recv.Err() directly, or by handing recv to a helper that does
// (handlers/rows_guard.go's abortOnRowsErr, which answers 500 instead of
// serving a short list).
func checksRowsErr(body *ast.BlockStmt, recv string) bool {
	found := false
	ast.Inspect(body, func(b ast.Node) bool {
		c, ok := b.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Err" {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == recv {
				found = true
			}
		}
		if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "abortOnRowsErr" {
			for _, a := range c.Args {
				if x, ok := a.(*ast.Ident); ok && x.Name == recv {
					found = true
				}
			}
		}
		return true
	})
	return found
}
