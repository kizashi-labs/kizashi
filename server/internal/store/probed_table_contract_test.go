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

// Existence probes — "does this table exist?" before querying it — are the most
// common guard in this codebase: 352 call sites across 105 distinct table names
// when this test was written. Their failure mode is silence. A probe naming a
// table no migration creates is false for ever, so the guarded code never runs
// and the caller is handed the fallback: an empty list, a default score, or a
// fabricated number. Nothing logs at Warn, nothing 500s, and the endpoint looks
// like a working feature with no data in it.
//
// schema_contract_test.go checks INSERT columns and update_column_contract_test.go
// checks UPDATE columns. Both catch a query that would fail loudly. This checks
// the guards that stop a query from ever being issued, which fail quietly.
//
// Found by the audit this test came from, each confirmed against a database
// built by running internal/store.RunMigrations over all 394 migrations:
//
//	iocs, dns_events, processes    scheduler/threat_hunt_automator.go
//
// That component hunted IOCs against three tables no migration creates, and its
// one existing table (network_connections) was queried with columns that do not
// exist (remote_ip, timestamp) and is written by no code at all. It had been
// running as a no-op goroutine on a 30-minute tick. Both of its routines were
// already covered, correctly, elsewhere: detection.IOCMatcher matches live
// events (with CIDR and domain-suffix support), scheduler.RetroIOCHunter covers
// historical events against new IOCs using the field names ingestion actually
// writes, and the builtin Sigma rule "Office Application Spawning Script
// Interpreter" (T1566.001) covers strictly more than its process-chain hunt.
// Repairing it would have produced duplicate alerts; it is gone.
//
// The remaining findings are listed in knownMissingProbedTables. They are not
// exemptions: each is a live defect with its consequence recorded there. The
// list ratchets — an entry the scan stops finding must be deleted, so fixing
// one cannot leave stale prose behind.

// probeRe captures the table name from the existence-probe forms used in this
// codebase: information_schema.tables (table_name), pg_tables (tablename),
// to_regclass, and the shared helper tableIsThere.
//
// **tableIsThere を足したのは、SQL が1か所にまとまったからです。**
// 2026-08-12 に `internal/api/handlers` の 79 個の確認を
// `tableIsThere(ctx, pool, "テーブル名")` に寄せました。SQL の文字列が
// 消えたので、上の3つだけでは名前が拾えなくなり、**この検査は
// 「抽出器が壊れています」で落ちました** —— 落ちてくれたので気づけました。
// 黙って 0 件になる作りだったら、そのまま通っていました。
var probeRe = regexp.MustCompile(
	`(?i)\btable_name\s*=\s*'([a-z_0-9]+)'` +
		`|\btablename\s*=\s*'([a-z_0-9]+)'` +
		`|\bto_regclass\('(?:public\.)?([a-z_0-9]+)'\)` +
		`|\btableIsThere\([^,]+,\s*[^,]+,\s*"([a-z_0-9]+)"\)`)

// probeSite is one existence probe found in the source.
type probeSite struct {
	file  string
	table string
}

func (p probeSite) String() string { return fmt.Sprintf("%s: probes for table %q", p.file, p.table) }

// sourceProbes scans non-test Go for existence probes naming a literal table.
//
// Probes whose table arrives in a variable are invisible here. export_handler.go
// is the one such caller: it probes the table of each entry in its exportTypes
// map. Those tables are covered because the map's literals are reached by the
// INSERT/UPDATE contract tests and by the export status endpoint, which reports
// available=false rather than pretending.
func sourceProbes(t *testing.T) []probeSite {
	t.Helper()
	root := filepath.Join("..", "..")
	var out []probeSite
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
		for _, m := range probeRe.FindAllStringSubmatch(string(b), -1) {
			for _, g := range m[1:] {
				if g != "" {
					out = append(out, probeSite{file: rel, table: strings.ToLower(g)})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return out
}

// knownMissingProbedTables are probe targets no migration creates. Each entry
// records what the permanently-false probe causes, not merely that it is absent.
var knownMissingProbedTables = map[string]string{
	"risk_score_history": "api/handlers/risk_scoring_handler.go: NOT a defect. This is a genuine " +
		"optional-table fallback — when absent the handler aggregates risk_scores " +
		"(which does exist) by date. Listed so the ratchet does not flag it.",
}

// TestEveryProbedTableExistsInMigrations is the gate.
func TestEveryProbedTableExistsInMigrations(t *testing.T) {
	schema := migrationSchema(t)
	probes := sourceProbes(t)
	if len(probes) < 50 {
		t.Fatalf("only %d existence probes parsed — the extractor is broken and this test would pass vacuously", len(probes))
	}

	found := map[string]bool{}
	var problems []string
	for _, p := range probes {
		if _, exists := schema[p.table]; exists {
			continue
		}
		found[p.table] = true
		if _, allowed := knownMissingProbedTables[p.table]; !allowed {
			problems = append(problems, p.String())
		}
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("存在しないテーブルを条件にしたガードです。ガードは恒久的に false になり、"+
			"保護されたコードは一度も実行されません: %s", p)
	}

	// Ratchet: an entry that is no longer found must be removed, so a fixed
	// defect cannot leave its description behind as though it were still live.
	for table := range knownMissingProbedTables {
		if !found[table] {
			t.Errorf("knownMissingProbedTables still lists %q, but the scan no longer finds "+
				"a probe for it. Delete the entry.", table)
		}
	}
}

// TestProbeExtractorWorks pins the extractor itself, so the gate above cannot
// start passing because the regex stopped matching.
func TestProbeExtractorWorks(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{"information_schema", `WHERE table_schema = 'public' AND table_name = 'alerts'`, "alerts"},
		{"pg_tables", `SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='agents'`, "agents"},
		{"to_regclass", `SELECT to_regclass('public.webhook_targets')`, "webhook_targets"},
		{"to_regclass bare", `SELECT to_regclass('events')`, "events"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := probeRe.FindStringSubmatch(tc.sql)
			if m == nil {
				t.Fatalf("probeRe did not match %q", tc.sql)
			}
			var got string
			for _, g := range m[1:] {
				if g != "" {
					got = g
				}
			}
			if got != tc.want {
				t.Errorf("extracted %q, want %q", got, tc.want)
			}
		})
	}
}
