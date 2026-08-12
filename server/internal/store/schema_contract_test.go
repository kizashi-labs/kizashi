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

// Every INSERT in the Go source must name only columns the migrations actually
// create.
//
// This is the single most productive bug class in this codebase. On 2026-08-03
// alone, six independent instances were found and fixed:
//
//	agents.os                 (#615)  存在しない列
//	alerts / agents 列違い     (#624)  書き込み経路が全損
//	ueba_anomalies            NOT NULL 列の書き漏れ
//	ueba_baselines            同上（隣のテーブルを両者とも見落としていた）
//	audit_logs.action         middleware 経路の監査ログが全損
//	agents.ip_address         エンロールメント経路が全損
//	vulnerabilities.*         スキャナと Wazuh 取込が全損
//
// They share a shape: the Go code is written against the schema someone
// *intended*, the migrations built a different one, and Postgres rejects the
// statement at runtime where an ON CONFLICT clause or a Debug-level log hides
// it. Nothing in CI touched a database on the unit path, so nothing caught it.
//
// This test needs no database. It derives the column set from the migration SQL
// and checks it against the INSERT column lists in the source. It is a contract
// test, not a SQL parser: anything it cannot parse confidently is skipped rather
// than guessed at, because a checker that cries wolf gets disabled.

var (
	createTableRe = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?\s*\((.*?)\n\s*\)\s*;`)
	dropTableRe   = regexp.MustCompile(`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?(\w+)"?`)
	// One ALTER TABLE may carry several comma-separated ADD COLUMN clauses, so
	// grab the whole statement and then every clause inside it. Matching only the
	// first clause makes this test report columns as missing that migration 202
	// plainly adds — a checker with that bug is worse than no checker.
	alterTableRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?(\w+)"?(.*?);`)
	// The trailing capture is the column's definition tail, up to the next clause
	// separator, so NOT NULL / DEFAULT can be read off it.
	addColumnRe    = regexp.MustCompile(`(?is)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?([^,]*)`)
	dropColumnRe   = regexp.MustCompile(`(?is)DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?"?(\w+)"?`)
	setNotNullRe   = regexp.MustCompile(`(?is)ALTER\s+COLUMN\s+"?(\w+)"?\s+SET\s+NOT\s+NULL`)
	dropNotNullRe  = regexp.MustCompile(`(?is)ALTER\s+COLUMN\s+"?(\w+)"?\s+DROP\s+NOT\s+NULL`)
	setDefaultRe   = regexp.MustCompile(`(?is)ALTER\s+COLUMN\s+"?(\w+)"?\s+SET\s+DEFAULT`)
	dropDefaultRe  = regexp.MustCompile(`(?is)ALTER\s+COLUMN\s+"?(\w+)"?\s+DROP\s+DEFAULT`)
	columnDefRe    = regexp.MustCompile(`^\s*"?(\w+)"?\s+([A-Za-z].*)$`)
	insertColumnRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+"?(\w+)"?\s*\(([^;]*?)\)\s*(?:VALUES|SELECT)`)
	plainIdentRe   = regexp.MustCompile(`^\w+$`)
)

// column is what the migrations end up declaring for one column.
//
// notNull without hasDefault is the interesting combination: an INSERT that does
// not name such a column is rejected outright. That is how the ueba_anomalies and
// ueba_baselines writes were lost — the Go code named a subset of the columns and
// every statement failed on a NOT NULL that had no default to fall back on.
type column struct {
	notNull    bool
	hasDefault bool
}

// required reports whether an INSERT must name this column for the statement to
// succeed.
func (c column) required() bool { return c.notNull && !c.hasDefault }

// parseColumnAttrs reads NOT NULL / DEFAULT off a column definition tail.
//
// PRIMARY KEY implies NOT NULL but NOT a default: `id UUID PRIMARY KEY` with no
// DEFAULT genuinely requires the INSERT to supply a value, and treating primary
// keys as always-defaulted would hide that. Verified to cost nothing here — both
// treatments produce zero violations against the current source, so the stricter
// one is free.
func parseColumnAttrs(tail string) column {
	u := strings.ToUpper(tail)
	return column{
		notNull:    strings.Contains(u, "NOT NULL") || strings.Contains(u, "PRIMARY KEY"),
		hasDefault: strings.Contains(u, "DEFAULT") || strings.Contains(u, "SERIAL") || strings.Contains(u, "GENERATED"),
	}
}

// stmt is one schema-changing statement, kept with its byte offset so a file's
// statements can be replayed in the order they appear. Order matters: a file that
// drops a table and recreates it means something different from one that creates
// then drops.
type stmt struct {
	pos  int
	kind string // "create" | "drop" | "alter"
	m    []string
}

// tableConstraintKeywords are the words that start a table-level constraint
// clause, which columnDefRe would otherwise mistake for a column name.
var tableConstraintKeywords = map[string]bool{
	"primary": true, "foreign": true, "unique": true, "check": true,
	"constraint": true, "exclude": true, "like": true,
}

// fileStatements returns one file's schema-changing statements in source order.
func fileStatements(sql string) []stmt {
	var out []stmt
	collect := func(re *regexp.Regexp, kind string) {
		locs := re.FindAllStringSubmatchIndex(sql, -1)
		ms := re.FindAllStringSubmatch(sql, -1)
		for i := range locs {
			out = append(out, stmt{pos: locs[i][0], kind: kind, m: ms[i]})
		}
	}
	collect(createTableRe, "create")
	collect(dropTableRe, "drop")
	collect(alterTableRe, "alter")
	sort.SliceStable(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

// migrationSchema replays every migration in the order internal/store/migrate.go
// applies them (filename order, then source order within a file) and returns the
// schema the database actually ends up with.
//
// The one rule that makes this worth doing rather than just unioning every column
// mentioned anywhere: CREATE TABLE IF NOT EXISTS on a table that already exists
// is a NO-OP in Postgres. When several migrations declare the same table with
// different shapes, the FIRST one is what the database has, and the later
// declaration's extra columns exist only if that migration also ALTERs them in.
//
// This is not hypothetical. audit_logs (006 vs 173) and yara_rules (041 vs 174)
// were both real bugs from exactly this. Six tables in this tree currently
// redeclare columns that only the first declaration's shape decides:
// api_endpoints, deception_events, email_security_events, incident_playbooks,
// response_actions, yara_rules. A union-based model reports those phantom columns
// as present, which is the wrong direction to be wrong in — the checker would
// stay green on the very bug it was written to catch.
func migrationSchema(t *testing.T) map[string]map[string]column {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	schema := map[string]map[string]column{}
	// Only CREATE establishes existence. An ALTER on a table this replay has not
	// created yet must not be allowed to stand in for one: migration 179 guards a
	// CREATE inside the ELSE branch of a DO block whose IF branch ALTERs, and the
	// ALTERs appear first in the file. Treating those ALTERs as "the table exists"
	// made the CREATE look like a redundant redeclaration and dropped every column
	// it declares — the checker then reported four columns as nonexistent that the
	// migration plainly creates. Same shape as the multi-clause ALTER bug in 202:
	// a checker that cries wolf gets disabled, so it has to be right about this.
	created := map[string]bool{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, s := range fileStatements(string(b)) {
			table := strings.ToLower(s.m[1])
			switch s.kind {
			case "drop":
				delete(schema, table)
				delete(created, table)

			case "create":
				if created[table] {
					continue // IF NOT EXISTS on an existing table: no-op
				}
				created[table] = true
				if schema[table] == nil {
					schema[table] = map[string]column{}
				}
				// Columns already known from an earlier ALTER are kept: in the
				// branch where those ALTERs ran, the table existed with a shape
				// this replay cannot see, so their presence is the safe reading.
				// The CREATE's own definitions win for the columns it declares.
				for _, line := range strings.Split(s.m[2], "\n") {
					line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ","))
					cm := columnDefRe.FindStringSubmatch(line)
					if cm == nil {
						continue
					}
					col := strings.ToLower(cm[1])
					if tableConstraintKeywords[col] {
						continue
					}
					schema[table][col] = parseColumnAttrs(cm[2])
				}

			case "alter":
				if schema[table] == nil {
					schema[table] = map[string]column{}
				}
				body := s.m[2]
				for _, a := range addColumnRe.FindAllStringSubmatch(body, -1) {
					schema[table][strings.ToLower(a[1])] = parseColumnAttrs(a[2])
				}
				for _, d := range dropColumnRe.FindAllStringSubmatch(body, -1) {
					delete(schema[table], strings.ToLower(d[1]))
				}
				for _, x := range setNotNullRe.FindAllStringSubmatch(body, -1) {
					if c, ok := schema[table][strings.ToLower(x[1])]; ok {
						c.notNull = true
						schema[table][strings.ToLower(x[1])] = c
					}
				}
				for _, x := range dropNotNullRe.FindAllStringSubmatch(body, -1) {
					if c, ok := schema[table][strings.ToLower(x[1])]; ok {
						c.notNull = false
						schema[table][strings.ToLower(x[1])] = c
					}
				}
				for _, x := range setDefaultRe.FindAllStringSubmatch(body, -1) {
					if c, ok := schema[table][strings.ToLower(x[1])]; ok {
						c.hasDefault = true
						schema[table][strings.ToLower(x[1])] = c
					}
				}
				for _, x := range dropDefaultRe.FindAllStringSubmatch(body, -1) {
					if c, ok := schema[table][strings.ToLower(x[1])]; ok {
						c.hasDefault = false
						schema[table][strings.ToLower(x[1])] = c
					}
				}
			}
		}
	}
	return schema
}

type sourceInsert struct {
	file    string
	table   string
	columns []string
}

// sourceInserts collects every INSERT whose column list is a plain identifier
// list. Dynamically built SQL is skipped — this test would rather miss a case
// than invent one.
func sourceInserts(t *testing.T) []sourceInsert {
	t.Helper()
	root := filepath.Join("..", "..")
	var out []sourceInsert
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
		for _, m := range insertColumnRe.FindAllStringSubmatch(string(b), -1) {
			var cols []string
			ok := true
			for _, c := range strings.Split(m[2], ",") {
				c = strings.ToLower(strings.Trim(strings.TrimSpace(c), `"`))
				if !plainIdentRe.MatchString(c) {
					ok = false
					break
				}
				cols = append(cols, c)
			}
			if ok && len(cols) > 0 {
				rel, _ := filepath.Rel(root, path)
				out = append(out, sourceInsert{file: rel, table: strings.ToLower(m[1]), columns: cols})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return out
}

func TestEveryInsertColumnExistsInMigrations(t *testing.T) {
	schema := migrationSchema(t)
	inserts := sourceInserts(t)
	if len(inserts) < 100 {
		t.Fatalf("only %d INSERTs parsed — the extractor is broken and this test would pass vacuously", len(inserts))
	}

	var problems []string
	for _, ins := range inserts {
		cols, known := schema[ins.table]
		if !known {
			// Table created outside the migrations (or by a CREATE this parser
			// cannot read). Out of scope rather than a guess.
			continue
		}
		for _, c := range ins.columns {
			if _, ok := cols[c]; !ok {
				problems = append(problems,
					fmt.Sprintf("%s: INSERT INTO %s names column %q, which no migration creates "+
						"— Postgres rejects the whole statement and the write is silently lost",
						ins.file, ins.table, c))
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// The mirror image of the test above: naming only columns that exist is not
// enough, because a column the INSERT omits can still sink the statement if it
// is NOT NULL with no default.
//
// This is the half that was missed on 2026-08-03. ueba_anomalies and
// ueba_baselines both had every named column present and correct, and every
// write still failed, because each table had picked up a second generation of
// NOT NULL columns from a later migration that the Go code never learned about.
// Nothing surfaced it: the error went to a Debug log and the caller saw success.
func TestEveryInsertSuppliesRequiredColumns(t *testing.T) {
	schema := migrationSchema(t)
	inserts := sourceInserts(t)

	var problems []string
	for _, ins := range inserts {
		cols, known := schema[ins.table]
		if !known {
			continue
		}
		named := make(map[string]bool, len(ins.columns))
		for _, c := range ins.columns {
			named[c] = true
		}
		for name, col := range cols {
			if col.required() && !named[name] {
				problems = append(problems,
					fmt.Sprintf("%s: INSERT INTO %s omits column %q, which is NOT NULL with no default "+
						"— Postgres rejects the whole statement and the write is silently lost",
						ins.file, ins.table, name))
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// The extractor must actually find things, or the tests above pass vacuously —
// the exact failure mode they exist to prevent.
func TestMigrationColumnExtractorWorks(t *testing.T) {
	schema := migrationSchema(t)

	for _, tc := range []struct{ table, col string }{
		{"agents", "ip_addresses"},     // CREATE TABLE, first declaration wins
		{"agents", "hostname"},         //
		{"ioc_entries", "source_feed"}, // added by a multi-clause ALTER (migration 202)
		{"audit_logs", "action"},       // 006's shape, not 173's
		{"audit_logs", "method"},       // contributed by 173's ALTER
		{"vulnerabilities", "affected_package"},
		{"ueba_baselines", "user_key"},
		{"rules", "content"},
	} {
		if _, ok := schema[tc.table][tc.col]; !ok {
			t.Errorf("extractor missed %s.%s — column-existence checks would pass vacuously", tc.table, tc.col)
		}
	}

	// And it must NOT invent columns. These are the names the code used to write
	// before 2026-08-03; if the extractor starts reporting them as present, it is
	// matching something it should not.
	for _, tc := range []struct{ table, col string }{
		{"agents", "ip_address"},
		{"vulnerabilities", "software_name"},
	} {
		if _, ok := schema[tc.table][tc.col]; ok {
			t.Errorf("extractor invented %s.%s — false negatives would follow", tc.table, tc.col)
		}
	}

	// CREATE TABLE IF NOT EXISTS on an existing table is a NO-OP, so a later
	// redeclaration contributes nothing unless it also ALTERs the column in.
	// These four are columns that only a second CREATE TABLE declares; a model
	// that unions every declaration reports them as present and then stays green
	// on writes Postgres would reject. That is how the audit_logs and yara_rules
	// bugs survived.
	for _, tc := range []struct{ table, col string }{
		{"response_actions", "triggered_by"},   // 001 wins over 008
		{"yara_rules", "rule_yaml"},            // 041 wins over 174
		{"deception_events", "attacker_ip"},    // 116 wins over 165
		{"incident_playbooks", "trigger_type"}, // 086 wins over 162
	} {
		if _, ok := schema[tc.table][tc.col]; ok {
			t.Errorf("%s.%s is only declared by a second CREATE TABLE IF NOT EXISTS, which Postgres "+
				"skips — reporting it as present defeats the check", tc.table, tc.col)
		}
	}

	// The NOT NULL model must be populated, or the required-column test above is
	// a no-op. These are the columns whose absence actually broke writes.
	for _, tc := range []struct{ table, col string }{
		{"audit_logs", "action"},          // the middleware audit-log break
		{"ueba_baselines", "username"},    // the UEBA baseline break
		{"ueba_baselines", "metric_name"}, //
		{"ueba_anomalies", "username"},    // the UEBA anomaly break
		{"events", "raw_data"},
		{"rules", "content"},
	} {
		if !schema[tc.table][tc.col].required() {
			t.Errorf("%s.%s should be NOT NULL with no default — the required-column check "+
				"would not catch an INSERT that omits it", tc.table, tc.col)
		}
	}

	// ...and must not mark defaulted columns as required, or the check floods.
	for _, tc := range []struct{ table, col string }{
		{"agents", "status"},      // has a DEFAULT
		{"audit_logs", "method"},  // ADD COLUMN ... NOT NULL DEFAULT ''
		{"audit_logs", "user_id"}, // plain nullable
	} {
		if schema[tc.table][tc.col].required() {
			t.Errorf("%s.%s is not required (it is nullable or defaulted) but the model says it is "+
				"— false positives would get this check disabled", tc.table, tc.col)
		}
	}
}
