package scheduler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A background worker whose existence check can never pass.
//
// Fourteen of the forty schedulers in this package guard their work with a
// probe against information_schema: does this table exist, does this column
// exist. The guard is right — a worker should not crash a deployment whose
// schema predates it. What it cannot do is tell "not yet" from "never".
//
// hunt_scheduler is the "never". saved_hunt_queries has no `scheduled` column,
// no migration adds one, nothing in this repository writes one, and there is no
// UI for it: scheduled hunting was never finished. The worker is registered in
// cmd/api, wakes every fifteen minutes, takes the guard, and returns. It has
// executed zero hunts on every deployment that has ever run. The only reason
// anyone knows is that someone read the code — which is the whole problem, and
// why this file exists rather than another log line.
//
// Only 3 of the 40 emit any metric, and there is no run-record table, so
// "ran and did nothing" and "never ran" are the same from outside for the other
// 37. This test cannot see that. What it can see is the narrower and more
// checkable thing: a probe that the migrated schema can never satisfy.

const (
	migrationsDir = "../../migrations"
	schedulerDir  = "."
)

// tableProbe matches `table_name = 'x'` and `tablename = 'x'`.
var tableProbe = regexp.MustCompile(`table_?name\s*=\s*'([a-z_][a-z0-9_]*)'`)

// columnProbe matches `column_name = 'x'`.
var columnProbe = regexp.MustCompile(`column_?name\s*=\s*'([a-z_][a-z0-9_]*)'`)

// createTable captures a table name and everything to the closing paren.
var createTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\((.*?)\n\s*\)\s*;`)

// addColumn matches `ALTER TABLE t ADD COLUMN [IF NOT EXISTS] c`.
var addColumn = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

// probe is one existence check found in a scheduler.
type probe struct {
	file   string
	table  string
	column string // empty for a table-only probe
}

// schemaProbes reads every probe out of the package's non-test sources.
//
// A file may probe several tables; a column probe is attributed to the table
// named nearest above it in the same statement, which is how all four column
// probes in this package are written.
func schemaProbes(t *testing.T, dir string) []probe {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []probe
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		out = append(out, probesIn(e.Name(), string(b))...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].table+out[i].column < out[j].table+out[j].column
	})
	return out
}

// probesIn reads the probes out of one file's source.
//
// Takes the source rather than a path so the comment handling is testable.
// With every probe in the tree living in real code, dropping stripLineComments
// changed nothing — and this file's own prose names `scheduled` a dozen times,
// which is exactly the input that would break it.
func probesIn(file, src string) []probe {
	src = stripLineComments(src)
	var out []probe
	seen := map[string]bool{}
	spans := tableProbe.FindAllStringSubmatchIndex(src, -1)
	for i, m := range spans {
		table := src[m[2]:m[3]]
		// A column probe belongs to this table if it appears before the next
		// table probe.
		end := len(src)
		if i+1 < len(spans) {
			end = spans[i+1][0]
		}
		cols := columnProbe.FindAllStringSubmatch(src[m[1]:end], -1)
		if len(cols) == 0 {
			if !seen[table] {
				out = append(out, probe{file, table, ""})
				seen[table] = true
			}
			continue
		}
		for _, c := range cols {
			key := table + "." + c[1]
			if !seen[key] {
				out = append(out, probe{file, table, c[1]})
				seen[key] = true
			}
		}
	}
	return out
}

// stripLineComments blanks `//` comments so a probe described in prose is not
// read as a probe. This file's own explanations name `scheduled` repeatedly.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// migratedSchema returns table → set of column names, from the migrations.
func migratedSchema(t *testing.T, dir string) map[string]map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	srcs := make([]string, 0, len(names))
	for _, name := range names {
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		srcs = append(srcs, string(b))
	}
	return schemaFrom(srcs)
}

// schemaFrom builds table → columns from migration sources, in order.
//
// Takes the sources rather than a path for the same reason as probesIn: with
// no migration comment happening to contain a CREATE TABLE, dropping
// stripSQLComments changed nothing.
func schemaFrom(srcs []string) map[string]map[string]bool {
	schema := map[string]map[string]bool{}
	for _, raw := range srcs {
		src := stripSQLComments(raw)
		for _, m := range createTable.FindAllStringSubmatch(src, -1) {
			table := strings.ToLower(m[1])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			for _, col := range columnNames(m[2]) {
				schema[table][col] = true
			}
		}
		for _, m := range addColumn.FindAllStringSubmatch(src, -1) {
			table := strings.ToLower(m[1])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			schema[table][strings.ToLower(m[2])] = true
		}
	}
	return schema
}

func stripSQLComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// columnNames pulls the leading identifier off each top-level line of a CREATE
// TABLE body, skipping table constraints.
func columnNames(body string) []string {
	var out []string
	depth := 0
	var cur strings.Builder
	flush := func() {
		f := strings.Fields(strings.TrimSpace(cur.String()))
		cur.Reset()
		if len(f) == 0 {
			return
		}
		name := strings.ToLower(strings.Trim(f[0], `"`))
		switch name {
		case "primary", "unique", "foreign", "check", "constraint", "exclude", "like":
			return
		}
		if regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(name) {
			out = append(out, name)
		}
	}
	for _, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				flush()
				continue
			}
		}
		cur.WriteRune(r)
	}
	flush()
	return out
}

// knownDeadProbes are probes the migrated schema cannot satisfy, with what each
// costs. An entry is a worker that runs and does nothing, forever.
//
// It ratchets both ways: a probe that starts passing must be deleted from here,
// or the list becomes a record of how things used to be.
var knownDeadProbes = map[string]string{
	"saved_hunt_queries.scheduled": "" +
		"hunt_scheduler.go。どのマイグレーションも作らず、リポジトリ内に書き手も " +
		"UI もありません。定期ハントは未完成で、ワーカーは15分ごとに起きて何もせず " +
		"戻ります。scheduled 列を足すだけでは足りず、真にする経路が要ります",
}

// The headline.
func TestEverySchedulerProbeCanBeSatisfied(t *testing.T) {
	probes := schemaProbes(t, schedulerDir)
	schema := migratedSchema(t, migrationsDir)

	if len(probes) < 10 {
		t.Fatalf("スキーマ確認が %d 件しか見つかりません。走査が届いていません", len(probes))
	}
	if len(schema) < 100 {
		t.Fatalf("マイグレーションのテーブルが %d 個しか見つかりません", len(schema))
	}

	for _, p := range deadProbes(probes, schema, knownDeadProbes) {
		t.Error(p)
	}
}

// deadProbes is separated out because on the passing path nothing is dead and
// the allowlist entry is present, so neither branch below is reached — a check
// that never fires reads the same as one that was removed.
func deadProbes(probes []probe, schema map[string]map[string]bool, allow map[string]string) []string {
	var problems []string
	live := map[string]bool{}

	for _, p := range probes {
		key := p.table
		if p.column != "" {
			key = p.table + "." + p.column
		}
		ok := schema[p.table] != nil
		if ok && p.column != "" {
			ok = schema[p.table][p.column]
		}
		if ok {
			live[key] = true
			continue
		}
		if _, waived := allow[key]; waived {
			continue
		}
		what := fmt.Sprintf("テーブル %s", p.table)
		if p.column != "" {
			what = fmt.Sprintf("%s.%s 列", p.table, p.column)
		}
		problems = append(problems, fmt.Sprintf(
			"%s が %s の存在を確認していますが、マイグレーションはそれを作りません。\n"+
				"  この確認は常に失敗するので、このワーカーは起きるたびに何もせず戻ります。\n"+
				"  症状は「その処理の結果が無い」だけで、処理する対象が無い状態と区別がつきません。",
			p.file, what))
	}

	for key := range allow {
		if live[key] {
			problems = append(problems, fmt.Sprintf(
				"knownDeadProbes の %q はもう存在します。削除してください", key))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestTheDeadProbeRuleActuallyFires(t *testing.T) {
	schema := map[string]map[string]bool{
		"agents": {"id": true, "hostname": true},
	}
	for _, tc := range []struct {
		name   string
		probes []probe
		allow  map[string]string
		want   int
	}{
		{"テーブルがある", []probe{{"x.go", "agents", ""}}, nil, 0},
		{"テーブルが無い", []probe{{"x.go", "ghosts", ""}}, nil, 1},
		{"列がある", []probe{{"x.go", "agents", "hostname"}}, nil, 0},
		{"列が無い", []probe{{"x.go", "agents", "scheduled"}}, nil, 1},
		{"列が無いが許可済み", []probe{{"x.go", "agents", "scheduled"}},
			map[string]string{"agents.scheduled": "理由"}, 0},
		{"許可が古い（もう存在する）", []probe{{"x.go", "agents", "hostname"}},
			map[string]string{"agents.hostname": "理由"}, 1},
		{"2件", []probe{{"x.go", "ghosts", ""}, {"y.go", "agents", "nope"}}, nil, 2},
	} {
		if got := deadProbes(tc.probes, schema, tc.allow); len(got) != tc.want {
			t.Errorf("%s: %d件 (want %d): %v", tc.name, len(got), tc.want, got)
		}
	}
}

// Both scanners have to recognise real statements, or the contract is
// satisfied by finding nothing on either side.
func TestTheSchemaScannersReadRealSources(t *testing.T) {
	probes := schemaProbes(t, schedulerDir)

	// The four column probes this package actually contains.
	want := map[string]bool{
		"api_keys.expires_at":                false,
		"saved_hunt_queries.scheduled":       false,
		"saved_hunt_queries.last_run_at":     false,
		"mdm_integrations.credential_expiry": false,
	}
	for _, p := range probes {
		if p.column == "" {
			continue
		}
		if _, ok := want[p.table+"."+p.column]; ok {
			want[p.table+"."+p.column] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("列の確認 %q を見つけられていません", k)
		}
	}

	schema := migratedSchema(t, migrationsDir)
	for _, tc := range []struct{ table, column string }{
		{"agents", "hostname"},
		{"alerts", "severity"},
		{"saved_hunt_queries", "last_run_at"},
		{"api_keys", "expires_at"},
	} {
		if !schema[tc.table][tc.column] {
			t.Errorf("マイグレーションから %s.%s を読めていません", tc.table, tc.column)
		}
	}
	// And the one that is genuinely absent must read as absent.
	if schema["saved_hunt_queries"]["scheduled"] {
		t.Error("saved_hunt_queries.scheduled が存在すると読めています。" +
			"どのマイグレーションも作らないはずです")
	}
}

// columnNames must not take a table constraint for a column, or every table
// gains phantom columns named "primary" and "unique" and the gate stops
// catching anything.
func TestColumnNamesSkipsTableConstraints(t *testing.T) {
	body := `
	  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	  agent_id UUID NOT NULL,
	  score NUMERIC(5,2) DEFAULT 0,
	  tags TEXT[] NOT NULL DEFAULT '{}',
	  UNIQUE(agent_id, score),
	  CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(id)`
	got := columnNames(body)
	want := []string{"id", "agent_id", "score", "tags"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("columnNames = %v, want %v", got, want)
	}
}

// The comment handling, driven directly. Both strippers were unexercised: no
// probe and no CREATE TABLE in the tree happens to sit inside a comment, so
// removing either changed no result. The inputs that would break them are
// ordinary — a note explaining a probe, a migration header listing the tables
// it declares — and this file is full of the first kind.
func TestCommentsAreNotReadAsCode(t *testing.T) {
	goSrc := `
// hunt_scheduler probes table_name = 'ghosts' AND column_name = 'phantom'
func x() {
	q := "table_name = 'agents' AND column_name = 'hostname'" // table_name = 'wraiths'
}`
	got := probesIn("x.go", goSrc)
	if len(got) != 1 {
		t.Fatalf("%d件 (want 1): %+v", len(got), got)
	}
	if got[0].table != "agents" || got[0].column != "hostname" {
		t.Errorf("読めた確認が違います: %+v", got[0])
	}

	sqlSrc := `
-- CREATE TABLE ghosts (id UUID PRIMARY KEY);
-- ALTER TABLE agents ADD COLUMN phantom TEXT;
CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY,
  hostname TEXT NOT NULL
);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS os_version TEXT;
`
	schema := schemaFrom([]string{sqlSrc})
	if _, ok := schema["ghosts"]; ok {
		t.Error("コメント内の CREATE TABLE をテーブルとして読んでいます")
	}
	if schema["agents"]["phantom"] {
		t.Error("コメント内の ADD COLUMN を列として読んでいます")
	}
	for _, col := range []string{"id", "hostname", "os_version"} {
		if !schema["agents"][col] {
			t.Errorf("agents.%s を読めていません", col)
		}
	}
}

// And a probe with no column attaches to its own table, not to the next one.
func TestAColumnProbeAttachesToItsOwnTable(t *testing.T) {
	src := `
	a := "table_name = 'first' AND column_name = 'alpha'"
	b := "table_name = 'second'"
	c := "table_name = 'third' AND column_name = 'gamma'"
	`
	got := probesIn("x.go", src)
	want := []probe{
		{"x.go", "first", "alpha"},
		{"x.go", "second", ""},
		{"x.go", "third", "gamma"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d件 (want %d): %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
