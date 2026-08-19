package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The compliance scorecard asked how many backups had succeeded by counting
//
//	SELECT COUNT(*) FROM backup_manifests WHERE status = 'success'
//
// Nothing in this repository has ever written 'success'. The producer writes
// 'completed', and so does the column default. The count was therefore always
// zero, and NIST CSF RC.RP-2 plus ISO 27001 A.17.1.1–A.17.1.3 reported
// 30/non_compliant on every deployment however many backups had in fact run.
//
// This is the same shape as the ingestion/detection vocabulary mismatches this
// package already guards: a producer and a consumer name the same thing
// differently, and SQL answers a mismatch with an empty result rather than an
// error. Nobody notices, because a compliance dashboard that reads
// "0 successful backups" looks like a finding rather than a bug.
//
// This test needs no database. It reads three sources and requires them to
// agree:
//
//	1. the CHECK constraint in migrations/432_backups.sql
//	2. the constants in internal/backup/status.go
//	3. every status literal in Go SQL that targets a backup table
//
// It is deliberately narrow: it only looks at statements naming `backups` or
// `backup_manifests`, so it cannot cry wolf about the dozen other tables with a
// status column.

var (
	// The CHECK clause on backups.status, e.g. CHECK (status IN ('a', 'b')).
	backupStatusCheckRe = regexp.MustCompile(`(?is)CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)`)
	// A single-quoted SQL literal.
	sqlLiteralRe = regexp.MustCompile(`'([^']*)'`)
	// A status predicate inside a SQL string: status = 'x', status <> 'x',
	// status IN ('x', 'y'). Captures the tail so every literal in it can be read.
	statusPredicateRe = regexp.MustCompile(`(?is)\bstatus\s*(?:=|<>|!=|\bIN\b)\s*(\(?[^)\n]*)`)
	// A statement targeting one of the two backup evidence tables.
	backupTableRe = regexp.MustCompile(`(?is)\b(?:FROM|INTO|UPDATE|JOIN)\s+"?(backups|backup_manifests)"?\b`)
	// The DEFAULT on a status column, e.g. status TEXT DEFAULT 'completed'.
	statusDefaultRe = regexp.MustCompile(`(?is)\bstatus\s+\w+(?:\s+NOT\s+NULL)?\s+DEFAULT\s+'([^']*)'`)
	// A Go constant declaration in internal/backup/status.go.
	goStatusConstRe = regexp.MustCompile(`(?m)^\s*Status\w+\s*=\s*"([^"]*)"`)
)

const backupTablesForVocabulary = "backups|backup_manifests"

// serverRoot walks up from this test's directory to the module root.
func serverRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("expected the module root at %s: %v", dir, err)
	}
	return dir
}

// migrationStatusVocabulary reads the CHECK constraint the schema puts on
// backups.status.
func migrationStatusVocabulary(t *testing.T, root string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found under %s", root)
	}
	vocab := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f) // #nosec G304 -- repo-local migration path
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(body)
		if !regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?backups"?\s*\(`).MatchString(text) {
			continue
		}
		m := backupStatusCheckRe.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		for _, lit := range sqlLiteralRe.FindAllStringSubmatch(m[1], -1) {
			vocab[lit[1]] = true
		}
	}
	return vocab
}

// goStatusVocabulary reads the exported constants in internal/backup/status.go.
func goStatusVocabulary(t *testing.T, root string) map[string]bool {
	t.Helper()
	path := filepath.Join(root, "internal", "backup", "status.go")
	body, err := os.ReadFile(path) // #nosec G304 -- repo-local source path
	if err != nil {
		t.Fatalf("read %s: %v — the backup status vocabulary has moved and this "+
			"test is no longer checking anything", path, err)
	}
	vocab := map[string]bool{}
	for _, m := range goStatusConstRe.FindAllStringSubmatch(string(body), -1) {
		vocab[m[1]] = true
	}
	return vocab
}

// backupSQLLiteral is one SQL string in the Go source that targets a backup
// table, with where it came from.
type backupSQLLiteral struct {
	file string
	line int
	sql  string
}

// collectBackupSQL walks the Go source for SQL touching the backup evidence
// tables. Two shapes are recognised:
//
//	a string literal that itself names the table  — the ordinary case
//	a call whose arguments are ("backups", "status = 'x'") — onboarding_handler
//
// Anything else is left alone; a checker that guesses gets switched off.
func collectBackupSQL(t *testing.T, root string) []backupSQLLiteral {
	t.Helper()
	var out []backupSQLLiteral
	fset := token.NewFileSet()
	tableName := regexp.MustCompile(`^(?:` + backupTablesForVocabulary + `)$`)

	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel, _ := filepath.Rel(root, path)

		lit := func(n ast.Node) (string, bool) {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return "", false
			}
			s, uerr := strconv.Unquote(bl.Value)
			return s, uerr == nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			// Shape 1: a SQL string that names a backup table itself.
			if s, ok := lit(n); ok && backupTableRe.MatchString(s) {
				out = append(out, backupSQLLiteral{rel, fset.Position(n.Pos()).Line, s})
				return true
			}
			// Shape 2: a call passing the table name and a predicate separately.
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			named := false
			for _, a := range call.Args {
				if s, ok := lit(a); ok && tableName.MatchString(s) {
					named = true
				}
			}
			if !named {
				return true
			}
			for _, a := range call.Args {
				s, ok := lit(a)
				if !ok || tableName.MatchString(s) {
					continue
				}
				if statusPredicateRe.MatchString(s) {
					out = append(out, backupSQLLiteral{rel, fset.Position(a.Pos()).Line, s})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// statusLiteralsIn pulls the quoted values out of every status predicate in one
// SQL string. Placeholders ($1) carry no literal and are skipped — passing the
// constant as a parameter is the preferred form.
func statusLiteralsIn(sql string) []string {
	var out []string
	for _, m := range statusPredicateRe.FindAllStringSubmatch(sql, -1) {
		for _, l := range sqlLiteralRe.FindAllStringSubmatch(m[1], -1) {
			out = append(out, l[1])
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheBackupStatusVocabularyIsOneVocabulary is the parity gate.
func TestTheBackupStatusVocabularyIsOneVocabulary(t *testing.T) {
	root := serverRoot(t)

	migration := migrationStatusVocabulary(t, root)
	goConsts := goStatusVocabulary(t, root)

	// Self-check: a scan that found nothing would pass everything below.
	if len(migration) < 2 {
		t.Fatalf("found %d status values in the backups CHECK constraint (%v). "+
			"The constraint has moved or changed shape and this test is measuring "+
			"almost nothing.", len(migration), sortedKeys(migration))
	}
	if len(goConsts) < 2 {
		t.Fatalf("found %d status constants in internal/backup/status.go (%v). "+
			"The constants have moved and this test is measuring almost nothing.",
			len(goConsts), sortedKeys(goConsts))
	}

	// Constants-versus-CHECK parity for `backups` is asserted by
	// TestStatusConstantsMatchTheirCheckConstraints, which does the same job for
	// every CHECK-constrained status column in the schema. What remains here is
	// the part specific to this pair of tables: the AST scan below, which reads
	// call sites where the table name and the predicate are separate arguments,
	// and backup_manifests, which has a DEFAULT rather than a CHECK.

	// Every status literal in SQL that targets a backup table must be a word the
	// vocabulary contains.
	sqls := collectBackupSQL(t, root)
	if len(sqls) < 4 {
		t.Fatalf("found only %d SQL statements targeting %s in the Go source. The "+
			"scan has drifted from how these queries are written and is no longer "+
			"checking the consumers.", len(sqls), backupTablesForVocabulary)
	}
	for _, s := range sqls {
		for _, lit := range statusLiteralsIn(s.sql) {
			if !migration[lit] {
				t.Errorf("%s:%d compares a backup status against %q, which nothing "+
					"writes. Allowed: %v. SQL answers a wrong word with an empty "+
					"result, not an error, so this reads as \"no backups\" for ever.",
					s.file, s.line, lit, sortedKeys(migration))
			}
		}
	}
}

// TestTheManifestStatusDefaultIsInTheVocabulary. backup_manifests has no CHECK
// constraint; its column DEFAULT is what a row gets when the producer omits the
// status. If that default drifts from the constants, rows written by any path
// that relies on it stop counting as evidence — the same silent zero, from the
// producer side this time.
func TestTheManifestStatusDefaultIsInTheVocabulary(t *testing.T) {
	root := serverRoot(t)
	goConsts := goStatusVocabulary(t, root)

	files, _ := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?backup_manifests"?\s*\((.*?)\n\s*\)\s*;`)
	found := false
	for _, f := range files {
		body, err := os.ReadFile(f) // #nosec G304 -- repo-local migration path
		if err != nil {
			continue
		}
		m := createRe.FindStringSubmatch(string(body))
		if m == nil {
			continue
		}
		d := statusDefaultRe.FindStringSubmatch(m[1])
		if d == nil {
			continue
		}
		found = true
		if !goConsts[d[1]] {
			t.Errorf("backup_manifests.status defaults to %q, which is not one of "+
				"the backup status constants %v", d[1], sortedKeys(goConsts))
		}
	}
	if !found {
		t.Fatal("no DEFAULT found on backup_manifests.status — the table has been " +
			"redefined and this test is measuring nothing")
	}
}
