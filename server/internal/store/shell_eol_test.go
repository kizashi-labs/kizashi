package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// A shell script committed with CRLF endings does not run on Linux. bash reads
// the trailing \r as part of the last token, so the file dies with errors that
// name a line number but not the cause:
//
//	line 16: set: -: invalid option
//	line 17: $'\r': command not found
//	line 38: syntax error near unexpected token `$'do\r''
//
// Nothing catches this before someone runs the script on Linux, and several of
// this repository's scripts are run rarely (installers, one-off measurement
// harnesses) or only from a workflow that has never been dispatched — so the
// gap between "committed broken" and "noticed" is unbounded.
//
// .gitattributes (`*.sh text eol=lf`) is the fix: it normalizes on the way into
// the index, so CRLF cannot be committed by a Windows checkout. This test is the
// guard for the case the attribute misses — a file added with `-text`, an
// attribute someone deletes, or a script that arrives through a path that skips
// the clean filter.
//
// It lives here for the same reason debt_ledger_test.go does: this is where the
// repository keeps its "read the files and assert the rest agrees" checks, and
// it needs neither a database nor a build tag.
func TestShellScriptsUseLFEndings(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	var scanned, crlf []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable path is not this test's business
		}
		if info.IsDir() {
			switch info.Name() {
			// .claude holds sibling git worktrees, each a full checkout whose
			// working-tree endings are the local machine's business, not main's.
			case ".git", ".claude", "node_modules", "vendor", ".next":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".sh" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		scanned = append(scanned, rel)

		b, err := os.ReadFile(path)
		if err != nil {
			return nil //nolint:nilerr
		}
		if bytes.Contains(b, []byte("\r")) {
			crlf = append(crlf, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	// Without this the test passes loudly when the walk is broken (wrong root,
	// an over-eager SkipDir) and finds nothing to check.
	if len(scanned) < 30 {
		t.Fatalf("only %d shell scripts found under %s — the walk is broken and this test "+
			"would pass vacuously", len(scanned), root)
	}

	sort.Strings(crlf)
	for _, f := range crlf {
		t.Errorf("%s contains CR — it will not run on Linux. Convert with `sed -i 's/\\r$//' %s`.\n"+
			"If your whole working tree is CRLF, the cause is core.autocrlf=true on a Windows "+
			"checkout rather than the committed content; `git rm --cached -r . && git reset --hard` "+
			"rewrites it using .gitattributes (`*.sh text eol=lf`).", f, f)
	}
}
