package rules

// Source-constraint conformance guard (no DB required).
//
// Every rule shipped by a migration is INSERTed with a `source` value, and the
// `rules_source_check` CHECK constraint (created in 001, redefined in 276/318)
// lists the permitted sources. If a migration INSERTs a source the constraint
// does not allow, PostgreSQL raises a HARD ERROR at INSERT time — it is NOT a
// silent drop — which aborts the migration transaction; RunMigrations then
// returns the error and cmd/api exits (os.Exit(1)), so api-server never boots.
//
// This exact failure shipped once: the parity batch (318-356) INSERTs 132 rules
// with source='builtin-parity', but the post-276 constraint did not list it, so
// applying migration 318 crashed api-server startup. The in-process parity/
// migration suites parse SQL but never apply the constraint, so they stayed
// green while a real DB seed failed. Migration 318 now widens the constraint
// before its first INSERT; this test locks that any INSERTed source is permitted
// by the constraint, so the next new source can't reintroduce the crash.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Form B: ALTER TABLE ... ADD CONSTRAINT rules_source_check CHECK (source = ANY (ARRAY[ ... ]))
var sourceConstraintArrayRe = regexp.MustCompile(`(?is)CONSTRAINT\s+rules_source_check\s+CHECK\s*\(\s*source\s*=\s*ANY\s*\(\s*ARRAY\s*\[(.*?)\]`)

// Form A: inline column CHECK (source IN ('a','b',...)) in the CREATE TABLE (001).
var sourceConstraintInRe = regexp.MustCompile(`(?is)CHECK\s*\(\s*source\s+IN\s*\((.*?)\)`)

var quotedLiteralRe = regexp.MustCompile(`'([^']*)'`)

// allowedRuleSources returns the effective permitted `source` set, i.e. the
// literals from the highest-sorted migration that (re)defines the constraint —
// later ADD CONSTRAINT statements REPLACE earlier ones, so last file wins.
func allowedRuleSources(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)

	var authoritative []string
	var authoritativeFile string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql := string(data)
		var lits []string
		for _, m := range sourceConstraintArrayRe.FindAllStringSubmatch(sql, -1) {
			lits = extractQuoted(m[1])
		}
		if len(lits) == 0 {
			for _, m := range sourceConstraintInRe.FindAllStringSubmatch(sql, -1) {
				lits = extractQuoted(m[1])
			}
		}
		if len(lits) > 0 {
			authoritative = lits
			authoritativeFile = filepath.Base(f)
		}
	}
	if len(authoritative) == 0 {
		t.Fatal("no rules_source_check definition found in any migration")
	}
	t.Logf("authoritative rules_source_check from %s: %v", authoritativeFile, authoritative)
	set := make(map[string]bool, len(authoritative))
	for _, s := range authoritative {
		set[s] = true
	}
	return set
}

func extractQuoted(s string) []string {
	var out []string
	for _, m := range quotedLiteralRe.FindAllStringSubmatch(s, -1) {
		if v := strings.ReplaceAll(m[1], "''", "'"); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// insertedSource holds one INSERTed source literal and where it came from.
type insertedSource struct {
	file  string
	value string
}

// scanInsertedSources returns every literal `source` value INSERTed into rules
// across all migrations. Rows that omit source (rely on DEFAULT) or set it via a
// non-literal expression are skipped — only quoted/dollar-quoted literals, which
// the constraint checks per row, are collected.
func scanInsertedSources(t *testing.T) []insertedSource {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)

	var out []insertedSource
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql := string(data)
		base := filepath.Base(f)
		for _, loc := range insertHeaderRe.FindAllStringSubmatchIndex(sql, -1) {
			cols := splitColumns(sql[loc[2]:loc[3]])
			srcIdx := -1
			for i, c := range cols {
				if strings.EqualFold(strings.TrimSpace(c), "source") {
					srcIdx = i
					break
				}
			}
			if srcIdx < 0 {
				continue // INSERT does not set source → DEFAULT applies
			}
			mode := strings.ToUpper(sql[loc[4]:loc[5]])
			region := sql[loc[1]:]
			var tuples [][]string
			if mode == "SELECT" {
				tuples = [][]string{scanSelectValues(region)}
			} else {
				tuples = scanTuples(region)
			}
			for _, tup := range tuples {
				if srcIdx >= len(tup) {
					continue
				}
				raw := strings.TrimSpace(tup[srcIdx])
				if !strings.HasPrefix(raw, "'") && !strings.HasPrefix(raw, "$") {
					continue // expression / DEFAULT, not a literal the check pins
				}
				out = append(out, insertedSource{file: base, value: unquoteScalar(raw)})
			}
		}
	}
	return out
}

// TestMigrationInsertedSourcesSatisfyConstraint fails if any migration INSERTs a
// rules.source that the rules_source_check constraint does not permit — the exact
// condition that crashes api-server startup at DB seed. Pure SQL parse; no DB.
func TestMigrationInsertedSourcesSatisfyConstraint(t *testing.T) {
	allowed := allowedRuleSources(t)
	sources := scanInsertedSources(t)

	// Guard against a blind parser (0 matches would pass vacuously — the same
	// green-tests/red-seed trap this test exists to close).
	if len(sources) == 0 {
		t.Fatal("scanned 0 INSERTed source literals — parser regressed")
	}

	var parity int
	seenBad := map[string]bool{}
	for _, s := range sources {
		if s.value == "builtin-parity" {
			parity++
		}
		if !allowed[s.value] {
			key := s.file + ":" + s.value
			if !seenBad[key] {
				seenBad[key] = true
				t.Errorf("migration %s INSERTs rules.source=%q, not permitted by rules_source_check %v — this aborts the migration transaction and blocks api-server startup",
					s.file, s.value, keys(allowed))
			}
		}
	}

	// The parity batch (318-356) is the regression this guard was built around:
	// lock that its 132 builtin-parity rows are both parsed and permitted.
	if !allowed["builtin-parity"] {
		t.Error("rules_source_check no longer permits 'builtin-parity' — parity migrations 318-356 will crash api-server at DB seed")
	}
	if parity < 132 {
		t.Errorf("parsed %d builtin-parity source literals, expected >= 132 (batch 318-356)", parity)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
