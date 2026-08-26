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

// A table created by application code rather than by a migration exists only if
// some code path happens to run first. Every reader has to remember to call
// ensureTable, the shape of a live deployment depends on which endpoint an
// operator opened and in what order, and nothing that reads the migration
// history — a restore review, a schema diff, the gate in this package that
// prepares every SELECT against the database — can see it.
//
// That last one is the quiet part. A statement reading a runtime-created table
// prepares cleanly in CI whenever a previous run left the table behind, so the
// schema check reports it as verified while nothing has declared its shape.
// Three of the four tables migration 382 picked up were in exactly that state:
// never declared, never listed as broken.
//
// The ensureTable calls themselves are fine and stay. What this pins is that a
// table's shape is declared somewhere a person can read without running the
// program.

// runtimeCreate finds `CREATE TABLE IF NOT EXISTS <name>` in Go source.
var runtimeCreate = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-z_][a-z0-9_]*)`)

// migrationCreate finds the same in a .sql migration.
var migrationCreate = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

// declaredOutsideMigrations are tables the application creates and no migration
// declares.
//
// It is empty, and an entry is a live gap rather than a waiver: the table's
// shape lives in Go source, so a fresh deployment has it only once the right
// endpoint is called, and nothing that reads the schema can see it.
//
// schema_migrations is the one legitimate exception and is handled below: the
// migration runner has to create its own bookkeeping table before it can run
// anything, so it cannot be declared by a migration.
var declaredOutsideMigrations = map[string]string{}

const migrationRunnerTable = "schema_migrations"

func goSourceRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return root
}

// tablesCreatedInGo returns every table name application code creates, mapped
// to the file that creates it.
func tablesCreatedInGo(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			// A doc comment describing the table is not a create.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, m := range runtimeCreate.FindAllStringSubmatch(line, -1) {
				rel, _ := filepath.Rel(root, path)
				if _, seen := out[m[1]]; !seen {
					out[m[1]] = rel
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}
	return out
}

// tablesDeclaredInMigrations returns every table name the migrations create.
func tablesDeclaredInMigrations(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	dir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			for _, m := range migrationCreate.FindAllStringSubmatch(line, -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

// The headline.
func TestEveryTableTheCodeCreatesIsAlsoDeclaredByAMigration(t *testing.T) {
	root := goSourceRoot(t)
	inGo := tablesCreatedInGo(t, root)
	inSQL := tablesDeclaredInMigrations(t, root)

	if len(inGo) == 0 {
		t.Fatal("Go 側の CREATE TABLE が1つも見つかりません。走査が届いていません")
	}
	if len(inSQL) < 100 {
		t.Fatalf("マイグレーションのテーブルが %d 個しか見つかりません", len(inSQL))
	}

	for _, p := range undeclaredTables(inGo, inSQL, declaredOutsideMigrations) {
		t.Error(p)
	}
}

// undeclaredTables is separated out because on the passing path nothing is
// undeclared and the allowlist is empty, so neither branch below is ever
// reached — a check that never fires reads the same as one that was removed.
func undeclaredTables(inGo map[string]string, inSQL map[string]bool, allow map[string]string) []string {
	var problems []string
	for table, file := range inGo {
		if table == migrationRunnerTable || inSQL[table] {
			continue
		}
		if _, waived := allow[table]; waived {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"%s が %s を実行時に作成していますが、どのマイグレーションも宣言していません。\n"+
				"  そのテーブルは、たまたま先に動いたコード経路があったときだけ存在します。\n"+
				"  読み手はすべて ensureTable を呼ぶことを覚えていなければならず、\n"+
				"  マイグレーション履歴を読む側からは見えません。", file, table))
	}
	for table := range allow {
		if inSQL[table] {
			problems = append(problems, fmt.Sprintf(
				"declaredOutsideMigrations の %q はマイグレーションで宣言済みです。削除してください", table))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestTheUndeclaredTableRuleActuallyFires(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inGo  map[string]string
		inSQL map[string]bool
		allow map[string]string
		want  int
	}{
		{"すべて宣言済み",
			map[string]string{"a": "x.go"}, map[string]bool{"a": true}, nil, 0},
		{"未宣言が1つ",
			map[string]string{"a": "x.go"}, map[string]bool{}, nil, 1},
		{"未宣言だが許可済み",
			map[string]string{"a": "x.go"}, map[string]bool{}, map[string]string{"a": "理由"}, 0},
		{"マイグレーションランナー自身は対象外",
			map[string]string{migrationRunnerTable: "migrate.go"}, map[string]bool{}, nil, 0},
		{"許可リストが古い（もう宣言済み）",
			map[string]string{"a": "x.go"}, map[string]bool{"a": true}, map[string]string{"a": "理由"}, 1},
	} {
		if got := undeclaredTables(tc.inGo, tc.inSQL, tc.allow); len(got) != tc.want {
			t.Errorf("%s: %d件 (want %d): %v", tc.name, len(got), tc.want, got)
		}
	}
}

// And the two scanners have to actually recognise the statements, or the
// contract is satisfied by finding nothing on either side.
func TestTheSchemaScannersRecogniseCreateStatements(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CREATE TABLE IF NOT EXISTS endpoint_tags (", "endpoint_tags"},
		{"\t\t`CREATE TABLE IF NOT EXISTS sandbox_submissions (", "sandbox_submissions"},
		{"create table if not exists lower_case (", "lower_case"},
	} {
		m := runtimeCreate.FindStringSubmatch(tc.in)
		if m == nil || m[1] != tc.want {
			t.Errorf("runtimeCreate(%q) = %v, want %q", tc.in, m, tc.want)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"CREATE TABLE alerts (", "alerts"},
		{"CREATE TABLE IF NOT EXISTS retro_rule_state (", "retro_rule_state"},
	} {
		m := migrationCreate.FindStringSubmatch(tc.in)
		if m == nil || m[1] != tc.want {
			t.Errorf("migrationCreate(%q) = %v, want %q", tc.in, m, tc.want)
		}
	}
	// An index is not a table.
	if migrationCreate.MatchString("CREATE INDEX IF NOT EXISTS idx_x ON y(z);") {
		t.Error("CREATE INDEX をテーブル宣言として数えています")
	}
}
