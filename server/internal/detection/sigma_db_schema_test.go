package detection

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Sigma DB loader's query used to reference four columns that do not exist:
// yara_rules.type, yara_rules.is_active, and custom_alert_rules.rule_yaml.
// Postgres rejects the whole statement on the first bad column, so the function
// never loaded a single DB rule for the entire life of the code — it errored,
// logged at Debug (invisible at the default Info level), and returned nil.
//
// Nothing caught it: no unit test touches a real database, and the integration
// suite is behind a build tag. The failure is invisible from the outside because
// "zero rules loaded" and "rules loaded but nothing matched" look identical.
//
// This test closes that specific hole without needing a database: it derives the
// column set from the migration SQL and asserts every column the query names
// actually exists. It is deliberately narrow — a schema-vs-query contract, not a
// SQL parser.

// migrationSchema returns table -> set of column names, built from CREATE TABLE
// and ALTER TABLE ... ADD COLUMN statements across every migration in order.
func migrationSchema(t *testing.T) map[string]map[string]bool {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?\s*\(`)
	alterRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?(\w+)"?\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?`)
	colRe := regexp.MustCompile(`^\s*"?(\w+)"?\s+[A-Za-z]`)

	schema := map[string]map[string]bool{}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	// Filename order is the apply order (internal/store/migrate.go).
	sortStrings(names)

	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sql := string(b)

		for _, m := range alterRe.FindAllStringSubmatch(sql, -1) {
			tbl, col := strings.ToLower(m[1]), strings.ToLower(m[2])
			if schema[tbl] == nil {
				schema[tbl] = map[string]bool{}
			}
			schema[tbl][col] = true
		}

		for _, loc := range createRe.FindAllStringSubmatchIndex(sql, -1) {
			tbl := strings.ToLower(sql[loc[2]:loc[3]])
			// CREATE TABLE IF NOT EXISTS against an existing table is a no-op, so
			// the FIRST definition wins — which is exactly why yara_rules kept
			// migration 041's shape and never gained 174's rule_yaml.
			if _, seen := schema[tbl]; seen {
				continue
			}
			cols := map[string]bool{}
			for _, line := range strings.Split(sql[loc[1]:], "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, ")") {
					break
				}
				if m := colRe.FindStringSubmatch(line); m != nil {
					kw := strings.ToUpper(m[1])
					switch kw {
					case "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT", "EXCLUDE":
						continue
					}
					cols[strings.ToLower(m[1])] = true
				}
			}
			schema[tbl] = cols
		}
	}
	return schema
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// The columns the loader query in sigma_db.go depends on.
func TestSigmaDBQueryColumnsExist(t *testing.T) {
	schema := migrationSchema(t)

	cols, ok := schema["rules"]
	if !ok {
		t.Fatalf("no CREATE TABLE for `rules` found in the migrations")
	}
	for _, col := range []string{"type", "content", "enabled"} {
		if !cols[col] {
			t.Errorf("sigma_db.go queries rules.%s, but no migration creates that column — the query would fail and load ZERO rules", col)
		}
	}
}

// The two dropped sources must stay out of the query. A single bad column
// anywhere in the statement takes the WHOLE loader down, so re-adding either
// table without first adding its columns silently disables every DB rule again —
// the exact regression, not a hypothetical one.
//
// This reads sigma_db.go's own source rather than the schema, because the schema
// assertions alone would keep passing if someone re-added the broken SQL.
func TestSigmaDBQueryDoesNotReadTheBrokenSources(t *testing.T) {
	src, err := os.ReadFile("sigma_db.go")
	if err != nil {
		t.Fatalf("read sigma_db.go: %v", err)
	}
	schema := migrationSchema(t)

	for _, bad := range []struct {
		table   string
		columns []string
		why     string
	}{
		{"yara_rules", []string{"type", "is_active"}, "it stores raw YARA text, not Sigma YAML"},
		{"custom_alert_rules", []string{"rule_yaml"}, "it stores a JSONB condition list, not Sigma YAML"},
	} {
		if !strings.Contains(string(src), "FROM "+bad.table) {
			continue
		}
		// Reading the table is only defensible once its columns actually exist.
		missing := []string{}
		for _, c := range bad.columns {
			if !schema[bad.table][c] {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			t.Errorf("sigma_db.go reads %s, but %v do not exist in any migration — Postgres rejects the whole statement, so ZERO DB rules load (%s)",
				bad.table, missing, bad.why)
		} else {
			t.Errorf("sigma_db.go reads %s again; its columns now exist, but confirm the content format is Sigma YAML before relying on it (%s)",
				bad.table, bad.why)
		}
	}
}

// The schema extractor itself must work, or the two tests above pass vacuously —
// the failure mode this whole file exists to prevent.
func TestMigrationSchemaExtractorFindsKnownColumns(t *testing.T) {
	schema := migrationSchema(t)

	for _, tc := range []struct{ table, col string }{
		{"rules", "name"},
		{"rules", "mitre_tags"},
		{"yara_rules", "content"},  // 041
		{"yara_rules", "category"}, // 085, via ALTER TABLE ADD COLUMN
		{"custom_alert_rules", "conditions"},
		{"agents", "id"},
	} {
		if !schema[tc.table][tc.col] {
			t.Errorf("extractor missed known column %s.%s — the column-existence tests would pass vacuously", tc.table, tc.col)
		}
	}
}
