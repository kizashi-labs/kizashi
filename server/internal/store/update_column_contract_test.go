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

// schema_contract_test.go checks that every INSERT names only columns the
// migrations create. UPDATE was not checked, and it fails the same way for the
// same reason — except that an UPDATE against a missing column is usually worse,
// because the write it was meant to perform is the whole point of the code path.
//
// Found by this test on the day it was written (all confirmed against the live
// migrated schema, not just the parser):
//
//	scheduled_reports.next_run_at   scheduler/report_generator.go
//
// The report generator selected due reports with a WHERE clause built from the
// columns it found, so a missing next_run_at simply removed the time filter:
// every enabled report was "due" on every 5-minute tick. It then advanced the
// schedule with `UPDATE scheduled_reports SET next_run_at = $1`, which fails
// with 42703 into a discarded error, so nothing ever advanced. Measured: three
// ticks produced three full reports for a schedule whose next_run was a day
// away — 288 files per report per day, for ever. That component is gone; the
// same table is driven correctly by internal/reports.Scheduler.
//
// knownMissingUpdateColumns is empty, and that is the point. It held four
// entries when this test was written, every one a write that could not land:
// per-agent config that returned 500 on every call, patch results that stayed
// pending while the deployment reported completed, duplicate alerts never
// linked to a parent, and API keys disabled without a recorded reason. Each was
// closed by adding the column the code was written against, or by removing a
// claim the platform could not support.
//
// The list ratchets in both directions — a new missing column fails the gate,
// and an entry that stops being found must be deleted — so it can never drift
// into a set of exemptions.

// updateSetRe captures the table and the SET clause of an UPDATE, stopping at
// WHERE / RETURNING / the end of the Go string literal.
var updateSetRe = regexp.MustCompile("(?is)\\bUPDATE\\s+\"?(\\w+)\"?\\s+SET\\s+(.*?)(?:\\bWHERE\\b|\\bRETURNING\\b|`|$)")

// updateSite is one UPDATE ... SET <column> pair found in the source.
type updateSite struct {
	file   string
	table  string
	column string
}

func (u updateSite) String() string {
	return fmt.Sprintf("%s: UPDATE %s SET %s", u.file, u.table, u.column)
}

// setClauseColumns splits a SET clause into the column names being assigned.
//
// It tracks parenthesis depth so a comma inside COALESCE(...) or
// jsonb_build_object(...) is not mistaken for a clause separator, and it gives
// up on the whole clause (returning ok=false) the moment an assignment target
// is not a plain identifier. Dynamically built SQL is skipped rather than
// guessed at, exactly as sourceInserts does: a checker that cries wolf gets
// switched off, and then it is worth nothing.
func setClauseColumns(clause string) ([]string, bool) {
	var parts []string
	depth, start := 0, 0
	for i, r := range clause {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, clause[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, clause[start:])

	var cols []string
	for _, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			return nil, false
		}
		name := strings.ToLower(strings.Trim(strings.TrimSpace(p[:eq]), `"`))
		if !plainIdentRe.MatchString(name) {
			return nil, false
		}
		cols = append(cols, name)
	}
	return cols, len(cols) > 0
}

// sourceUpdates collects every UPDATE ... SET whose assignment targets are all
// plain identifiers.
func sourceUpdates(t *testing.T) []updateSite {
	t.Helper()
	root := filepath.Join("..", "..")
	var out []updateSite
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 -- repo-local source path
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range updateSetRe.FindAllStringSubmatch(string(b), -1) {
			cols, ok := setClauseColumns(m[2])
			if !ok {
				continue
			}
			table := strings.ToLower(m[1])
			for _, c := range cols {
				out = append(out, updateSite{file: rel, table: table, column: c})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return out
}

// knownMissingUpdateColumns are UPDATE targets no migration creates. Each is a
// real defect that predates this test; each is listed with what the missing
// column costs, so the list reads as a worklist rather than an amnesty.
//
// Most of these sites first ask information_schema whether the column exists
// and skip the write when it does not. That turns a runtime error into a
// feature that is permanently, silently inert — the same failure the backups
// table had, and the reason a contract test is needed at all: the guard makes
// the bug invisible to logs, to tests, and to the operator.
var knownMissingUpdateColumns = map[string]string{}

// TestEveryUpdateColumnExistsInMigrations is the gate.
func TestEveryUpdateColumnExistsInMigrations(t *testing.T) {
	schema := migrationSchema(t)
	updates := sourceUpdates(t)

	// Self-check: an extractor that has drifted would pass everything below.
	if len(updates) < 200 {
		t.Fatalf("only %d UPDATE ... SET assignments parsed — the extractor is "+
			"broken and this test would pass vacuously", len(updates))
	}

	seen := map[string]bool{}
	var problems []string
	for _, u := range updates {
		cols, known := schema[u.table]
		if !known {
			// The migration parser did not find this table. That is a limit of the
			// parser, not evidence of a bug — sandbox_submissions is a live table it
			// cannot see — so say nothing rather than guess.
			continue
		}
		if _, has := cols[u.column]; has {
			continue
		}
		key := u.String()
		seen[key] = true
		if _, allowed := knownMissingUpdateColumns[key]; !allowed {
			problems = append(problems, key)
		}
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("%s — no migration creates this column. The UPDATE fails with "+
			"SQLSTATE 42703, or is skipped by a column-existence guard, and either "+
			"way the write this code path exists to perform does not happen.", p)
	}

	// Ratchet: an allowlisted entry that is no longer found has been fixed (or
	// moved), and its recorded consequence is now misleading. Delete it.
	var stale []string
	for key := range knownMissingUpdateColumns {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("knownMissingUpdateColumns still lists %q, but the scan no longer "+
			"finds it. Remove the entry so the list keeps describing the code.", s)
	}
}

// TestTheUpdateSetExtractorWorks pins the parsing rules the gate depends on, so
// a regression in the splitter shows up here rather than as a quietly shrinking
// set of checked statements.
func TestTheUpdateSetExtractorWorks(t *testing.T) {
	cases := []struct {
		name   string
		clause string
		want   []string
		ok     bool
	}{
		{"simple", "a = $1, b = $2", []string{"a", "b"}, true},
		{"commas inside a call are not separators",
			"tags = COALESCE(tags, '[]'::jsonb) || jsonb_build_array($1::text), updated_at=NOW()",
			[]string{"tags", "updated_at"}, true},
		{"quoted identifier", `"status" = $1`, []string{"status"}, true},
		{"nested calls", "m = COALESCE(m, jsonb_build_object('a', 1, 'b', 2)), t = NOW()",
			[]string{"m", "t"}, true},
		{"a non-identifier target gives up on the whole clause",
			"data->>'x' = $1, b = $2", nil, false},
		{"no assignment at all", "nonsense", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := setClauseColumns(tc.clause)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %v)", ok, tc.ok, got)
			}
			if ok && strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
		})
	}
}
