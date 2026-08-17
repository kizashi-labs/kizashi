package store

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Where a column's status vocabulary is fixed by a CHECK constraint, the Go
// constants that name those statuses have to match it exactly. When they drift,
// nothing errors at build time and nothing errors at review time; the write
// fails at runtime with 23514, and every caller in this codebase discards that
// error or turns it into a generic 500.
//
// Two live instances, both fixed in the changes this test accompanies:
//
//	live_response_commands   Cancel wrote status='failed'. The CHECK allows
//	                         pending/running/completed/error/timeout. Every
//	                         cancellation failed and the command stayed pending.
//	backups                  the compliance scorecard counted status='success'.
//	                         The producer writes 'completed'. Four controls
//	                         reported non-compliance regardless of the truth.
//
// The registry below is the mechanism; adding a third table is one entry.

// statusVocabularyCase pairs a table whose status column is CHECK-constrained
// with the Go file that names those statuses.
type statusVocabularyCase struct {
	table string
	// goFile is relative to the server module root.
	goFile string
	// constRe captures the string value of each status constant in goFile.
	constRe *regexp.Regexp
	// why is shown when the two disagree, so the failure explains the cost.
	why string
}

var statusVocabularyCases = []statusVocabularyCase{
	{
		table:   "live_response_commands",
		goFile:  "internal/store/live_response_store.go",
		constRe: regexp.MustCompile(`(?m)^\s*QueuedCommand\w+\s*=\s*"([^"]*)"`),
		why: "the live-response queue and the interactive terminal both write this " +
			"column; a word outside the constraint makes the write fail with 23514 " +
			"and leaves the command in whatever state it was already in",
	},
	{
		table:   "backups",
		goFile:  "internal/backup/status.go",
		constRe: regexp.MustCompile(`(?m)^\s*Status\w+\s*=\s*"([^"]*)"`),
		why: "the nightly dump writes this column and the compliance scorecard " +
			"counts it; a mismatch reports zero successful backups on a system " +
			"that is backing up correctly",
	},
}

var (
	// A CHECK on a status column, in either spelling Postgres accepts in DDL.
	statusCheckRe = regexp.MustCompile(`(?is)CHECK\s*\(\s*"?status"?\s+IN\s*\(([^)]*)\)`)
	quotedLiteral = regexp.MustCompile(`'([^']*)'`)
	// A later migration may replace the constraint outright.
	addStatusConstraintRe = regexp.MustCompile(
		`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?%s"?[^;]*?ADD\s+CONSTRAINT[^;]*?CHECK\s*\(\s*"?status"?\s+IN\s*\(([^)]*)\)`)
)

// moduleRoot returns the server module root from this package's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("expected the module root at %s: %v", dir, err)
	}
	return dir
}

// createTableBody returns the column list of the CREATE TABLE that createRe
// matches, or "" when the file does not declare that table.
//
// Scoping to the body matters: migration 017 declares live_response_sessions
// and live_response_commands in one file, and a CHECK search over the whole
// file returns the sessions table's vocabulary (active/closed/expired) for
// whichever table was asked about.
func createTableBody(text string, createRe *regexp.Regexp) string {
	loc := createRe.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	// createRe ends on the opening parenthesis of the column list.
	depth := 0
	for i := loc[1] - 1; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return text[loc[1]:i]
			}
		}
	}
	return text[loc[1]:]
}

// checkConstraintVocabulary reads the status values a table's CHECK constraint
// allows, as the database will actually end up enforcing them.
//
// The first CREATE wins, not the last. Every table in this repository is
// created with CREATE TABLE IF NOT EXISTS, so a second migration that declares
// the same table is a no-op for the constraint — only its ADD COLUMN statements
// take effect. That is not a hypothetical: migration 017 creates
// live_response_commands with 'error' in its vocabulary and 059 re-declares it
// with 'failed'. 059 never ran, the code was written against 059, and every
// cancellation failed with 23514 for as long as both files have existed. A
// reader that took the last declaration would have agreed with the code and
// missed the bug entirely.
//
// A later ALTER TABLE ... ADD CONSTRAINT does replace the constraint, so that
// is honoured in file order.
func checkConstraintVocabulary(t *testing.T, root, table string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found under %s", root)
	}
	sort.Strings(files)

	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?` + table + `"?\s*\(`)
	alterRe := regexp.MustCompile(strings.ReplaceAll(addStatusConstraintRe.String(), "%s", table))

	var vocab []string
	created := false
	for _, f := range files {
		body, err := os.ReadFile(f) // #nosec G304 -- repo-local migration path
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(body)

		if body := createTableBody(text, createRe); !created && body != "" {
			if m := statusCheckRe.FindStringSubmatch(body); m != nil {
				vocab = nil
				for _, lit := range quotedLiteral.FindAllStringSubmatch(m[1], -1) {
					vocab = append(vocab, lit[1])
				}
			}
			created = true
		}
		if m := alterRe.FindStringSubmatch(text); m != nil {
			vocab = nil
			for _, lit := range quotedLiteral.FindAllStringSubmatch(m[1], -1) {
				vocab = append(vocab, lit[1])
			}
		}
	}
	sort.Strings(vocab)
	return vocab
}

// goConstantVocabulary reads the status constants declared in a Go file.
func goConstantVocabulary(t *testing.T, root string, c statusVocabularyCase) []string {
	t.Helper()
	path := filepath.Join(root, c.goFile)
	body, err := os.ReadFile(path) // #nosec G304 -- repo-local source path
	if err != nil {
		t.Fatalf("read %s: %v — the status constants for %s have moved and this "+
			"test is no longer checking anything", path, err, c.table)
	}
	seen := map[string]bool{}
	var vocab []string
	for _, m := range c.constRe.FindAllStringSubmatch(string(body), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			vocab = append(vocab, m[1])
		}
	}
	sort.Strings(vocab)
	return vocab
}

// TestStatusConstantsMatchTheirCheckConstraints is the gate.
func TestStatusConstantsMatchTheirCheckConstraints(t *testing.T) {
	root := moduleRoot(t)

	if len(statusVocabularyCases) < 2 {
		t.Fatal("the registry has shrunk; this test is checking almost nothing")
	}

	for _, c := range statusVocabularyCases {
		t.Run(c.table, func(t *testing.T) {
			schema := checkConstraintVocabulary(t, root, c.table)
			goConsts := goConstantVocabulary(t, root, c)

			// Self-checks: either side coming back empty would make the comparison
			// below pass without comparing anything.
			if len(schema) < 2 {
				t.Fatalf("found %d status values in the CHECK constraint on %s (%v). "+
					"The constraint has moved or changed shape and this case is "+
					"measuring almost nothing.", len(schema), c.table, schema)
			}
			if len(goConsts) < 2 {
				t.Fatalf("found %d status constants in %s (%v). They have moved and "+
					"this case is measuring almost nothing.", len(goConsts), c.goFile, goConsts)
			}

			if strings.Join(goConsts, ",") != strings.Join(schema, ",") {
				t.Errorf("the Go constants and the schema disagree about %s.status:\n"+
					"  %s: %v\n  CHECK constraint:   %v\n%s",
					c.table, c.goFile, goConsts, schema, c.why)
			}
		})
	}
}

// TestNoStatusLiteralOutsideTheVocabulary scans the SQL in the Go source for
// status comparisons against these tables and requires every literal to be one
// the constraint accepts.
//
// This is the half that caught Cancel: the word 'failed' was written directly
// into the UPDATE, so no amount of agreement between constants and schema would
// have found it. Statements that pass the status as a placeholder are the
// preferred form and carry no literal to check.
func TestNoStatusLiteralOutsideTheVocabulary(t *testing.T) {
	root := moduleRoot(t)

	// Two shapes, kept separate on purpose. A single greedy pattern that tried to
	// cover both ran past `SET status=$2, output='キャンセルされました'` and
	// reported the output text as a status. A comparison takes exactly one
	// literal; an IN takes the parenthesised list and nothing after it.
	statusCompare := regexp.MustCompile(`(?is)\bstatus\s*(?:=|<>|!=)\s*'([^']*)'`)
	statusIn := regexp.MustCompile(`(?is)\bstatus\s+IN\s*\(([^)]*)\)`)

	for _, c := range statusVocabularyCases {
		t.Run(c.table, func(t *testing.T) {
			allowed := map[string]bool{}
			for _, s := range checkConstraintVocabulary(t, root, c.table) {
				allowed[s] = true
			}
			if len(allowed) < 2 {
				t.Fatalf("no CHECK vocabulary for %s; nothing to check against", c.table)
			}

			tableRe := regexp.MustCompile(`(?is)\b(?:FROM|INTO|UPDATE|JOIN)\s+"?` + c.table + `"?\b`)
			statements := 0
			err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return err
				}
				body, rerr := os.ReadFile(path) // #nosec G304 -- repo-local source path
				if rerr != nil {
					return nil
				}
				rel, _ := filepath.Rel(root, path)
				// Split on backticks so each raw SQL literal is examined on its own;
				// otherwise a status predicate in one query is attributed to a table
				// named in the next.
				for _, chunk := range strings.Split(string(body), "`") {
					if !tableRe.MatchString(chunk) {
						continue
					}
					statements++
					var found []string
					for _, pm := range statusCompare.FindAllStringSubmatch(chunk, -1) {
						found = append(found, pm[1])
					}
					for _, pm := range statusIn.FindAllStringSubmatch(chunk, -1) {
						for _, lit := range quotedLiteral.FindAllStringSubmatch(pm[1], -1) {
							found = append(found, lit[1])
						}
					}
					for _, lit := range found {
						if allowed[lit] {
							continue
						}
						keys := make([]string, 0, len(allowed))
						for k := range allowed {
							keys = append(keys, k)
						}
						sort.Strings(keys)
						t.Errorf("%s compares %s.status against %q, which the CHECK "+
							"constraint rejects. Allowed: %v. The statement fails with "+
							"23514 at runtime, where this codebase discards it.",
							rel, c.table, lit, keys)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk: %v", err)
			}
			if statements < 2 {
				t.Fatalf("found only %d SQL literals touching %s; the scan has drifted "+
					"from how these queries are written", statements, c.table)
			}
		})
	}
}
