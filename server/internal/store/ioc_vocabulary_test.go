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

// ioc_entries used to carry three duplicated pairs of columns, and readers
// disagreed about which half of each was authoritative:
//
//	type          NOT NULL, CHECK (hash|ip|domain|url|email)
//	ioc_type      nullable, unconstrained
//
//	is_active     what store.SetActive toggles
//	enabled       NOT NULL DEFAULT true, updated by nothing after insert
//
//	severity      1-10, set by every importer
//	threat_level  NOT NULL DEFAULT 5, left there by every writer but one
//
// Of the six writers, four never set ioc_type at all: manual adds through
// store/ioc.go, the TAXII importer, the STIX importer, and the bulk add. So an
// indicator's ioc_type is usually NULL while its type is always present.
//
// scheduler.RetroIOCHunter read the second column of each pair. The nullable
// one was the serious part: a NULL fails Scan, pgx ends iteration on a scan
// error, and one manually-added indicator therefore aborted the whole batch.
// Measured before that was fixed:
//
//	well-formed IOC alone                           -> domains=1
//	one NULL-ioc_type row ahead of it by first_seen  -> domains=0
//
// It reads type, is_active and severity now — the same three cmd/detection's
// ListActiveIOCs uses for live matching, so the two paths agree about which
// indicators are live and how severe they are.
//
// Migration 379 dropped ioc_type, enabled and threat_level once every reader
// and both writers had moved. 203 had added them as compatibility shims, saying
// so in its own header, and back-filled them once — nothing kept them in step
// afterwards, which is the whole of the divergence.
//
// Two gates remain, and they check different things. The source scan catches a
// query naming a dropped column before it reaches a database, with a message
// saying which column to use instead; the migration check catches the columns
// coming back. A query against a dropped column would fail at runtime with
// 42703, but the failures this file was written about were all silent ones —
// so the point is to fail early and legibly rather than at 3am.

var (
	// A SQL string literal mentioning the IOC table.
	iocStatementRe = regexp.MustCompile("(?s)`[^`]*\\bioc_entries\\b[^`]*`")
	// An INSERT. A writer that fills BOTH halves of a duplicated pair is what
	// keeps the duplication survivable — feed_scheduler.go sets type and
	// ioc_type to the same value — so writes are not the divergence this looks
	// for. Only reads are.
	iocInsertRe = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+"?ioc_entries"?\b`)
	// The half of each pair that is nullable, stale, or defaulted.
	deprecatedIOCColumnRe = regexp.MustCompile(`\b(ioc_type|threat_level|enabled)\b`)
)

// stripGoComments removes comments before the scan.
//
// The statement regex cannot tell an opening backtick from a closing one, so a
// comment sitting between two SQL strings reads as if it were inside one — and
// a comment explaining which column was WRONG mentions that column by name.
// The gate is about what the code does, not what it says about itself. `//` is
// only a comment when not preceded by `:`, so URLs survive.
func stripGoComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:])//.*$`).ReplaceAllString(src, "$1")
}

// iocReadSite is one SQL statement touching ioc_entries with a deprecated column.
type iocReadSite struct {
	file   string
	column string
}

func (s iocReadSite) String() string { return fmt.Sprintf("%s: ioc_entries.%s", s.file, s.column) }

// knownDeprecatedIOCColumnReads is empty and must stay so: the columns it
// tracked no longer exist. It held four entries when this gate was written —
// three in the enrichment handler and one in the sandbox handler — and each
// cost something: enrichment answered "never seen" about indicators the team
// had entered themselves, and sandbox correlation reported indicators an
// analyst had switched off.
var knownDeprecatedIOCColumnReads = map[string]string{}

// sourceIOCReads scans non-test Go for SQL touching ioc_entries and reports
// every deprecated column each statement names.
func sourceIOCReads(t *testing.T) []iocReadSite {
	t.Helper()
	root := filepath.Join("..", "..")
	seen := map[string]bool{}
	var out []iocReadSite

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, stmt := range iocStatementRe.FindAllString(stripGoComments(string(b)), -1) {
			if iocInsertRe.MatchString(stmt) {
				continue
			}
			for _, m := range deprecatedIOCColumnRe.FindAllStringSubmatch(stmt, -1) {
				key := rel + ": ioc_entries." + m[1]
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, iocReadSite{file: rel, column: m[1]})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return out
}

// TestNoNewReadersOfTheDeprecatedIOCColumns is the gate.
func TestNoNewReadersOfTheDeprecatedIOCColumns(t *testing.T) {
	sites := sourceIOCReads(t)

	found := map[string]bool{}
	var problems []string
	for _, s := range sites {
		key := s.String()
		found[key] = true
		if _, allowed := knownDeprecatedIOCColumnReads[key]; !allowed {
			problems = append(problems, key)
		}
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("ioc_entries の重複列のうち権威でない側を参照しています。"+
			"type / is_active / severity を使ってください（live matching と同じ組）: %s", p)
	}

	// Ratchet: an entry that is no longer found must go, so the list always
	// describes live divergence rather than history.
	for key := range knownDeprecatedIOCColumnReads {
		if !found[key] {
			t.Errorf("knownDeprecatedIOCColumnReads still lists %q, but the scan no "+
				"longer finds it. Delete the entry.", key)
		}
	}
}

// TestTheRetroHunterUsesTheAuthoritativeColumns pins the one this was written
// for: retroactive hunting must agree with live matching about which
// indicators are live.
func TestTheRetroHunterUsesTheAuthoritativeColumns(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "scheduler", "retro_ioc_hunter.go"))
	if err != nil {
		t.Fatalf("read retro hunter: %v", err)
	}
	stmts := iocStatementRe.FindAllString(string(src), -1)
	if len(stmts) == 0 {
		t.Fatal("retro hunter has no ioc_entries statement — the extractor is broken")
	}
	for _, stmt := range stmts {
		for _, bad := range []string{"ioc_type", "threat_level", "enabled"} {
			if regexp.MustCompile(`\b` + bad + `\b`).MatchString(stmt) {
				t.Errorf("レトロIOCハンターが %q を参照しています。"+
					"ライブ照合 (cmd/detection ListActiveIOCs) は type / is_active / severity を読みます", bad)
			}
		}
	}
}

// TestTheIOCVocabularyExtractorWorks stops the gate passing because the regex
// stopped matching.
func TestTheIOCVocabularyExtractorWorks(t *testing.T) {
	sample := "q := `SELECT value, ioc_type FROM ioc_entries WHERE enabled = true`"
	stmts := iocStatementRe.FindAllString(stripGoComments(sample), -1)
	if len(stmts) != 1 {
		t.Fatalf("statement extractor matched %d, want 1", len(stmts))
	}
	cols := deprecatedIOCColumnRe.FindAllString(stmts[0], -1)
	if len(cols) != 2 {
		t.Fatalf("column extractor found %v, want ioc_type and enabled", cols)
	}

	// A statement about another table must not be picked up — threat_intel_iocs
	// has its own ioc_type column and is not this table.
	for _, other := range []string{
		"q := `SELECT enabled FROM threat_feeds`",
		"q := `SELECT id, ioc_type FROM threat_intel_iocs`",
	} {
		if got := iocStatementRe.FindAllString(other, -1); len(got) != 0 {
			t.Errorf("extractor matched a non-IOC statement: %v", got)
		}
	}

	// A writer filling both halves is not divergence.
	insert := "q := `INSERT INTO ioc_entries (type, ioc_type, value) VALUES ($1,$1,$2)`"
	stmt := iocStatementRe.FindString(insert)
	if stmt == "" {
		t.Fatal("extractor missed an INSERT statement")
	}
	if !iocInsertRe.MatchString(stmt) {
		t.Error("INSERT detector did not recognise an INSERT")
	}
}

// A comment naming a deprecated column must not be mistaken for a use of it —
// the fix for each site says which column it moved away from.
func TestCommentsAreNotScannedForIOCColumns(t *testing.T) {
	src := "// is_active, not enabled: this used to read threat_level\n" +
		"q := `SELECT value FROM ioc_entries WHERE is_active = true`"
	stripped := stripGoComments(src)
	for _, stmt := range iocStatementRe.FindAllString(stripped, -1) {
		if cols := deprecatedIOCColumnRe.FindAllString(stmt, -1); len(cols) != 0 {
			t.Errorf("コメント中の列名が使用として検出されました: %v", cols)
		}
	}
	// And the statement itself is still found.
	if len(iocStatementRe.FindAllString(stripped, -1)) != 1 {
		t.Error("コメント除去で文そのものが失われました")
	}
}

// TestTheDuplicatedIOCColumnsAreGone reads the migrations rather than the
// source: a reader can be moved back one query at a time, but the columns
// coming back is what would make the whole divergence possible again.
func TestTheDuplicatedIOCColumnsAreGone(t *testing.T) {
	schema := migrationSchema(t)
	cols, ok := schema["ioc_entries"]
	if !ok {
		t.Fatal("ioc_entries not found in the migrations — the parser is broken")
	}
	// The columns that replaced them must be there, or this would pass by
	// having lost the table's contents rather than its duplicates.
	for _, want := range []string{"type", "is_active", "severity"} {
		if _, present := cols[want]; !present {
			t.Errorf("ioc_entries.%s がありません。移行先の列が失われています", want)
		}
	}
	for _, gone := range []string{"ioc_type", "enabled", "threat_level"} {
		if _, present := cols[gone]; present {
			t.Errorf("ioc_entries.%s が復活しています。"+
				"重複列は migration 379 で削除されました — type / is_active / severity を使ってください", gone)
		}
	}
}
