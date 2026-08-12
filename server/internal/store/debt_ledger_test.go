package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The debt ledger (docs/技術的負債と改善計画.md + docs/debt/*.md) is append-heavy:
// nearly every PR adds an entry. Splitting it by priority narrows the range in
// which two PRs collide, but the two failures that actually cost time on
// 2026-08-03 do not announce themselves as conflicts at all:
//
//   - Duplicate IDs. main took P5-11 for `agents.os` while a branch took P5-11
//     for the LOLBin work; P5-15 went to both the Wazuh and the Defender entry.
//     Appends at different offsets do not conflict, so git merges them cleanly
//     and the file ends up with two sections claiming the same ID.
//   - Sections lost in a merge resolution. P5-11 and P5-12 disappeared from main
//     entirely. Nothing failed; the content was simply gone until someone
//     noticed and re-landed it under new numbers.
//
// Both are silent, so both need a checker rather than better discipline. This
// one needs no database and no network — it reads the markdown.
//
// It lives in internal/store next to the schema contract test because that is
// where the repository's other "derive the truth from files and assert the rest
// agrees" checks are, and because it wants no build tag.

var (
	debtSectionRe = regexp.MustCompile(`(?m)^### (P\d+-\w+)\. (.*)$`)
	debtIndexRe   = regexp.MustCompile(`(?m)^- ` + "`" + `(P\d+-\w+)` + "`")
	debtRetiredRe = regexp.MustCompile("`(P\\d+-\\w+)`")
)

const (
	debtIndexPath = "../../../docs/技術的負債と改善計画.md"
	debtDir       = "../../../docs/debt"
)

// debtEntry is one ledger item and the file it lives in.
type debtEntry struct {
	id    string
	title string
	file  string
}

func readDebtSections(t *testing.T) []debtEntry {
	t.Helper()
	entries, err := os.ReadDir(debtDir)
	if err != nil {
		t.Fatalf("read %s: %v", debtDir, err)
	}
	var out []debtEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(debtDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range debtSectionRe.FindAllStringSubmatch(string(b), -1) {
			out = append(out, debtEntry{id: m[1], title: strings.TrimSpace(m[2]), file: e.Name()})
		}
	}
	return out
}

func readDebtIndex(t *testing.T) (listed []string, retired map[string]bool) {
	t.Helper()
	b, err := os.ReadFile(debtIndexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	text := string(b)
	for _, m := range debtIndexRe.FindAllStringSubmatch(text, -1) {
		listed = append(listed, m[1])
	}
	retired = map[string]bool{}
	// The retired-ID note is a blockquote; take the IDs out of that line only, so
	// a stray backticked ID elsewhere in the index cannot silently retire an entry.
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "退役した ID") {
			continue
		}
		for _, m := range debtRetiredRe.FindAllStringSubmatch(line, -1) {
			retired[m[1]] = true
		}
	}
	return listed, retired
}

// An ID may name exactly one entry. This is the check that would have caught
// both P5-11 collisions and the P5-15 one — none of which git flagged.
func TestDebtLedgerIDsAreUnique(t *testing.T) {
	sections := readDebtSections(t)
	if len(sections) < 20 {
		t.Fatalf("only %d ledger entries found — the parser is broken and this test would pass vacuously", len(sections))
	}

	seen := map[string]debtEntry{}
	for _, s := range sections {
		if prev, dup := seen[s.id]; dup {
			t.Errorf("%s is used twice: %s (%s) and %s (%s)\n"+
				"  Pick the next free number. Two PRs appending at different offsets merge "+
				"cleanly, so nothing else catches this.\n"+
				"  If you are hitting this repeatedly on a long-lived branch: the number is "+
				"only safe once main stops moving under you. Merge main FIRST, renumber LAST, "+
				"and renumber only YOUR entries — a blanket sed rewrites main's too, which "+
				"has happened. Sequential IDs cannot be collision-free across concurrent PRs; "+
				"this gate makes the collision loud, it does not prevent it.",
				s.id, prev.file, prev.title, s.file, s.title)
			continue
		}
		seen[s.id] = s
	}
}

// Index and body must agree in both directions. A section that vanishes in a
// merge resolution leaves its index row behind (and vice versa), which is what
// makes this detectable at all — the loss itself is invisible.
func TestDebtLedgerIndexMatchesSections(t *testing.T) {
	sections := readDebtSections(t)
	listed, retired := readDebtIndex(t)

	inIndex := map[string]bool{}
	for _, id := range listed {
		inIndex[id] = true
	}
	inBody := map[string]bool{}
	for _, s := range sections {
		inBody[s.id] = true
	}

	var problems []string
	for _, s := range sections {
		if !inIndex[s.id] {
			problems = append(problems, fmt.Sprintf(
				"%s exists in docs/debt/%s but is missing from the index — add a row to 項目一覧", s.id, s.file))
		}
	}
	for _, id := range listed {
		if !inBody[id] {
			problems = append(problems, fmt.Sprintf(
				"%s is listed in the index but no docs/debt/*.md defines it — a section was probably "+
					"dropped in a merge resolution (this is how P5-11 and P5-12 were lost)", id))
		}
	}
	// A retired ID must stay retired: reusing a freed number makes older PRs and
	// commit messages point at the wrong entry.
	for _, s := range sections {
		if retired[s.id] {
			problems = append(problems, fmt.Sprintf(
				"%s is recorded as retired in the index but %s defines it — retired numbers are not "+
					"recycled, because existing PRs and commit messages still refer to them", s.id, s.file))
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// Entries must live under the priority file their ID names, or the index's
// "which file holds P4-2" promise stops being true.
func TestDebtLedgerEntriesLiveUnderTheirPriority(t *testing.T) {
	for _, s := range readDebtSections(t) {
		prio, _, _ := strings.Cut(s.id, "-")
		if want := prio + ".md"; s.file != want {
			t.Errorf("%s is in docs/debt/%s but its ID says it belongs in docs/debt/%s", s.id, s.file, want)
		}
	}
}

// Thirty files across docs/ and the Go tree cite the ledger by ID ("see ... P4-2").
// A citation of an ID that does not exist reads as documented when it is not —
// the same false-green shape as an inert rule, applied to prose. P2-1c was one:
// cited from the CI cost doc, never written.
func TestDebtLedgerCitationsResolve(t *testing.T) {
	sections := readDebtSections(t)
	known := map[string]bool{}
	for _, s := range sections {
		known[s.id] = true
	}
	_, retired := readDebtIndex(t)

	root := filepath.Join("..", "..", "..")
	citeRe := regexp.MustCompile(`\bP\d-\w+\b`)
	var problems []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable path is not this test's business
		}
		if info.IsDir() {
			// Skip vendored and generated trees, and the ledger itself (the index
			// legitimately names retired IDs).
			switch info.Name() {
			case ".git", "node_modules", "vendor", "gen", "debt":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".md" && ext != ".go" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == filepath.Join("docs", "技術的負債と改善計画.md") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil //nolint:nilerr
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "技術的負債と改善計画") {
				continue // only lines that actually cite the ledger
			}
			for _, id := range citeRe.FindAllString(line, -1) {
				if known[id] || retired[id] {
					continue
				}
				problems = append(problems, fmt.Sprintf(
					"%s cites ledger entry %s, which no docs/debt/*.md defines — either the entry was "+
						"never written or its number changed; a citation that resolves to nothing reads "+
						"as documented when it is not", rel, id))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
