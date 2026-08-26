package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// A Python file committed with CRLF endings runs fine — and that is the problem.
//
// Unlike a CRLF shell script, which dies loudly on Linux (see shell_eol_test.go),
// a CRLF .py file executes on every platform. What breaks instead is everything
// that reads the file as text:
//
//   - every line shows as changed in a diff, so the real edit is invisible
//   - a merge between an LF branch and a CRLF branch conflicts on every line
//   - a mutation spec that pins an exact string stops matching
//
// This actually happened: seven mutation specs flipped to CRLF through a Windows
// working tree and surfaced days later as a whole-file conflict in an unrelated
// PR. Nobody wrote CRLF on purpose; the checkout did it, and nothing in the
// repository objected.
//
// .gitattributes (`*.py text eol=lf`) is the fix: it normalizes on the way into
// the index, so a Windows checkout cannot commit CRLF. This test is the guard for
// the case the attribute misses — a file added with `-text`, an attribute someone
// deletes, or a file that arrives through a path that skips the clean filter.
//
// This repository keeps its mutation specs, its snapshot generator, and its
// ratchet recalibrators in Python, so the blast radius is the whole
// self-checking apparatus rather than one script.
//
// It lives next to shell_eol_test.go for the same reason that one does: this is
// where the repository keeps its "read the files and assert the rest agrees"
// checks, and it needs neither a database nor a build tag.
func TestPythonFilesUseLFEndings(t *testing.T) {
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
			case ".git", ".claude", "node_modules", "vendor", ".next", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".py" {
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
	if len(scanned) < 60 {
		t.Fatalf("only %d Python files found under %s — the walk is broken and this test "+
			"would pass vacuously", len(scanned), root)
	}

	sort.Strings(crlf)
	for _, f := range crlf {
		t.Errorf("%s contains CR. It still runs, but every line reads as changed in a diff "+
			"and exact-string matchers (the mutation specs) stop matching. "+
			"Convert with `sed -i 's/\\r$//' %s`.\n"+
			"If your whole working tree is CRLF, the cause is core.autocrlf=true on a Windows "+
			"checkout rather than the committed content; `git rm --cached -r . && git reset --hard` "+
			"rewrites it using .gitattributes (`*.py text eol=lf`).", f, f)
	}
}
