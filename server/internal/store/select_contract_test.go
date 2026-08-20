package store

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SELECT was the one statement kind with no contract.
//
//	schema_contract_test.go          INSERT column lists
//	update_column_contract_test.go   UPDATE ... SET columns
//	probed_table_contract_test.go    "does this table exist?" guards
//	(nothing)                        SELECT
//
// That is the gap the last three quiet defects in this tree came through.
// GetDeliveryLog selected event_type, attempt and created_at from a table with
// none of the three; the patch-deployment roll-up read an updated_at that no
// migration creates; IOC enrichment read three columns off the deprecated half
// of a duplicated pair. Each returned an error the caller discarded, so the
// endpoint answered 200 with an empty body.
//
// Rather than parse SELECT — aliases, joins, CTEs, lateral subqueries, casts,
// window functions — this hands each statement to Postgres and stops at Parse.
// pgx's Prepare sends Parse/Describe/Sync, so the server resolves every table,
// column, function and operator in the statement against the real migrated
// schema and answers with an SQLSTATE, without executing anything. It catches
// strictly more than a column-name checker would: 42P01 for a missing table,
// 42703 for a missing column, 42883 for a missing function or an operator that
// does not exist between two types, 42803 for a GROUP BY that cannot run, and
// 22P02 for a literal compared against a column of the wrong type.
//
// Scope and its limit, stated because a gate that quietly covers less than it
// appears to is worse than none. Only complete, static SQL literals are
// checked: a query assembled at runtime from fragments and Sprintf cannot be
// prepared. It found 52 disagreements when it was written; 21 remain, and the
// count printed by the test is the live one.
//
// The runtime-assembled statements are the gap, and it is not small — around 74
// of them. Everything in this codebase that builds a WHERE clause from user
// filters lands there, which is most of the hunting and reporting surface.
// Closing it needs the queries themselves to change shape — a fixed statement
// with parameters instead of a concatenation — so it is a separate piece of
// work, not something this gate can reach.
//
// What remains is in knownBrokenSelects with what each one costs.

// selectLiteralRe captures a backtick string. Go's raw string is the only form
// used for SQL in this tree.
var selectLiteralRe = regexp.MustCompile("(?s)`([^`]*)`")

// selectStartRe recognises a statement this gate can check. WITH is included
// because half the reporting queries are CTEs.
var selectStartRe = regexp.MustCompile(`(?i)^(SELECT|WITH)\s`)

// interpolationRe marks a literal as a fragment of a runtime-assembled query.
// Those cannot be prepared, so they are skipped and reported rather than
// silently dropped.
var interpolationRe = regexp.MustCompile(`%[sdvqt]|%\+v`)

// schemaFailure is an SQLSTATE that means the statement disagrees with the
// schema, as opposed to being malformed or depending on the environment.
//
// 42601 (syntax_error) is deliberately absent. A literal that is one arm of a
// concatenation ends mid-statement and produces it, and that says nothing about
// the schema. Those are counted as fragments.
// clauseSuppliedLater are the SQLSTATEs a missing later arm can produce all by
// itself. A concatenated statement's first arm may aggregate without its
// GROUP BY, or SELECT DISTINCT without its ORDER BY, and Postgres will say so —
// about a query that is never run in that form.
//
// The others are not like that. A table that does not exist does not start
// existing because " LIMIT 10" is appended, and neither does a column, an
// operator between two types, or a mistyped literal. Those stay checked on
// arms, which is most of what this gate is for: skipping arms wholesale would
// have dropped 45 literals from the 1377 it covers.
var clauseSuppliedLater = map[string]bool{
	"42803": true, // needs a GROUP BY the later arm supplies
	"42P10": true, // SELECT DISTINCT needing the later arm's ORDER BY
}

var schemaFailure = map[string]string{
	"42P01": "テーブルがありません",
	"42703": "列がありません",
	"42883": "関数または演算子がありません",
	"42803": "GROUP BY が不正です",
	"42P10": "列参照が不正です",
	"22P02": "リテラルの型が列と合いません",
}

// environmentDependentSelects resolve or not according to what is installed in
// the database rather than to anything in this repository, so they are exempt
// and are NOT ratcheted — an entry here going green in CI and red locally is
// the expected behaviour, not a stale entry to delete.
var environmentDependentSelects = map[string]string{
	"internal/api/handlers/data_retention_handler.go: [42883] function hypertable_size(regclass) does not exist": "TimescaleDB の関数。CI の timescaledb イメージには存在します",
	"internal/api/handlers/system_handler.go: [42P01] relation \"pg_stat_statements\" does not exist":            "任意の拡張。未導入の環境があるのは想定内で、呼び出し側も存在確認をしています",
	"internal/store/migrate.go: [42P01] relation \"schema_migrations\" does not exist":                           "マイグレーションランナー自身が直前に CREATE します",
	"internal/store/system_updates_store.go: [42P01] relation \"schema_migrations\" does not exist":              "同じ表を読みます。migration ファイルではなくランナーが CREATE するので、ファイルから組んだスキーマには現れません。読めなかった場合は updater 側が「スキーマは動いていない」と決めつけず、ロールバックを部分的として扱います",
}

// knownBrokenSelects are the statements that disagree with the migrated schema.
// Each entry records what the failure costs, not merely that it exists. The map
// ratchets: an entry the scan stops finding must be deleted, so the list can
// never drift into describing history.
//
// Nothing repairable is left. Every entry below is a feature whose data does
// not exist, which is the owner's call rather than a repair.
//
// The easy shape — a column that exists under another name — has been worked
// through: `time` for `timestamp`, `detected_at`/`assessed_at`/`last_sync_at`
// for `created_at`/`last_fetched_at`, `resource_id` for `resource`,
// `full_name`/`email` for `display_name`/`username`, `agent_version` for
// `version`, `is_active` for `enabled`, `value` for `setting_value`.
//
// Not every one of those was a rename, and assuming so would have been wrong.
// The insider-threat and UEBA screens joined `users` on a username, and `users`
// is this product's console-account table (email, password_hash, role) while
// ueba_anomalies.username is an endpoint OS account. No column on `users` is
// the right one, because the two are different populations and the schema holds
// no mapping between them. The join is gone rather than repointed.
//
// The tables that were consolidated or renamed have had their readers moved:
// endpoint_hardening_assessments and endpoint_hardening onto
// hardening_assessments, iocs onto ioc_entries, vuln_findings onto
// vulnerabilities. Those were not all one-line substitutions — the consolidated
// hardening table keeps per-check outcomes in a findings jsonb array rather than
// as columns, so its readers unnest it.
//
// What is left in this group is different in kind: risk_score_history has no
// counterpart anywhere. No migration has ever created it and nothing writes it,
// so its readers cannot be repointed. It needs the table built or the feature
// removed, and that is the owner's call rather than a repair.
//
// compliance_checks sat here with it until #543. It turned out to have a
// counterpart after all — compliance_scores (042), which POST /compliance/score
// actually fills — so the export moved onto it and the entry is gone. The
// distinction that matters is not "the table is missing" but "is anything
// writing what this reader wants, under any name": here something was.
//
// retro_rule_state used to sit here with them, and the note said the retro
// hunter's resume position was never saved. That was wrong. The scheduler
// creates the table itself at startup, so the watermark did persist — what was
// true was only the first half, that no migration declared it. Three other
// tables were in the same position and were not listed at all, because a
// previous run had already created them in the test database and their readers
// therefore prepared cleanly. Migration 382 declares all four.
//
// Two of the column repairs were not renames either, and taking them as such
// would have produced a query that runs and answers wrongly — worse than one
// that fails loudly.
//
// `rules.mitre_tactic` has no counterpart column, but the data is there: ATT&CK
// technique IDs live in `mitre_tags` (text[]), so the tactic roll-up reads the
// array and folds it with detection.TacticForTechnique instead of grouping in
// SQL. A rule carrying several techniques must not be counted once per tactic
// per technique, so the fold counts distinct rule ids per tactic — which is what
// the original COUNT(DISTINCT r.id) meant.
//
// The MTTD join went the other way. It named three columns that do not exist
// (e.id, a.event_id, e.created_at), and Postgres could only report the first.
// Renaming all three would have produced a runnable query returning NULL for
// ever, because nothing links an alert to its triggering event: alerts.event_ids
// is absent from SaveAlert's INSERT, events.alert_id has no writer at all, and
// ingestion's INSERT INTO events does not return the row's id, so the server
// never learns it. The metric is nil ("not computed") rather than 0, and the
// query is gone rather than repaired into a silent zero.
//
// The src_country entry has gone too, and not by being repaired — the
// statement is deleted. Its handler could never run: no migration creates the
// column, no agent sets it, and the server-side GeoIP enrichment the proto note
// assumes exists nowhere. It now answers 501 with what is missing, rather than
// failing as though the failure were transient. The dashboard was rendering
// FALLBACK_GEO_THREATS on that failure — China 142 critical, Russia 89, North
// Korea 54 — invented attack origins, on the screen a SOC opens first.
//
// The most expensive entry this list ever held has already gone.
// internal/tenant.GetStats counted agents, users and alerts WHERE org_id = $1
// on three tables with no org_id column, discarded all three errors and
// returned (stats, nil), so every organization's usage read as zero. The column
// was not the defect: it belonged to a parallel `organizations` table no
// foreign key pointed at, while every tenant_id in the schema references
// `tenants`. Migration 380 removed the table, the package and the routes.
var knownBrokenSelects = map[string]string{
	// ── tables no migration creates, or that were consolidated away ──────────
	"internal/api/handlers/risk_scoring_handler.go: [42P01] relation \"risk_score_history\" does not exist": "" +
		"どのマイグレーションも作成しません。リスクスコアの推移グラフが空になります",

	// ── columns whose data does not exist anywhere, under any name ───────────
	// These three are not renames in disguise. Each was checked against the
	// migrated schema and against what the pipeline actually writes, and in
	// every case the value the query wants is produced by nothing.
	"internal/scheduler/hunt_scheduler.go: [42703] column \"scheduled\" does not exist": "" +
		"saved_hunt_queries に scheduled はありません。列を足しても真にする書き手が" +
		"どこにも無く、定期ハントは1件も起動しません",
}

// isConcatenationArm reports whether the literal ending at end (the index just
// past its closing backtick) is joined to something else with `+`.
//
// It is detected from the source rather than from the SQL because an arm can be
// a perfectly well-formed statement on its own, with nothing in the text to
// give it away — the incidents list is `<select …> + where + <group by …>`, and
// its first arm parses fine right up to the point where Postgres notices it
// aggregates without a GROUP BY.
//
// An arm is still checked, but only for the failures a later arm cannot
// explain. See clauseSuppliedLater.
func isConcatenationArm(src string, end int) bool {
	for i := end; i < len(src); i++ {
		switch src[i] {
		case ' ', '\t':
			continue
		case '+':
			return true
		default:
			return false
		}
	}
	return false
}

// selectSite is one static SELECT literal found in the source.
type selectSite struct {
	file string
	sql  string
	// arm marks a literal that is concatenated with something else, so what
	// Postgres sees here is one part of a statement rather than the statement.
	arm bool
}

// staticSelects collects every complete, static SELECT/WITH literal in non-test
// Go, and separately counts the fragments it cannot check.
func staticSelects(t *testing.T) (sites []selectSite, fragments int) {
	t.Helper()
	root := filepath.Join("..", "..")
	seen := map[string]bool{}

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
		src := string(b)
		// **コメントの中の SQL は SQL ではありません。** この走査は生の
		// テキストを見るので、説明のために `SELECT … finding` のように
		// バッククォートで囲んで書いた一文が、本物の literal と見分けが
		// つきません。実際に 2026-08-13 に起きました —— 直した関数の
		// 由来を書いたコメントが、そのまま「スキーマと一致しない SELECT」
		// として報告されました。**在りもしないクエリを直せと言う検査は、
		// 次に免除リストへ逃がされます。**
		comments, cerr := commentSpans(src)
		if cerr != nil {
			return fmt.Errorf("%s を読めません: %w", path, cerr)
		}
		for _, loc := range selectLiteralRe.FindAllStringSubmatchIndex(src, -1) {
			if insideAny(comments, loc[0]) {
				continue
			}
			sql := strings.TrimSpace(src[loc[2]:loc[3]])
			if !selectStartRe.MatchString(sql) {
				continue
			}
			if interpolationRe.MatchString(sql) {
				fragments++
				continue
			}
			arm := isConcatenationArm(src, loc[1])
			key := rel + "\x00" + sql
			if seen[key] {
				continue
			}
			seen[key] = true
			sites = append(sites, selectSite{file: rel, sql: sql, arm: arm})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return sites, fragments
}

// TestEverySelectAgreesWithTheSchema is the gate.
func TestEverySelectAgreesWithTheSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// The database must be a faithful replica of the migrations, or a "missing"
	// column would only mean this database is behind. Checked rather than
	// assumed: the gate would otherwise report the schema's own drift as a
	// hundred code defects.
	assertSchemaMatchesMigrations(t, pool)

	// 床は実測に寄せてあります。**500 のままだと、走査が半分死んでも
	// 通ります** —— 件数が減ったことと、直したことの区別が付きません。
	// 実測: 1265（2026-08-13、コメントを除いたあと。除く前は 1267 で、
	// 差の2件はコメントの中の一文でした）。
	sites, fragments := staticSelects(t)
	if len(sites) < 1200 {
		t.Fatalf("only %d static SELECTs found — the extractor is broken and this "+
			"test would pass nearly vacuously", len(sites))
	}
	t.Logf("static SELECT/WITH literals checked: %d (%d runtime-assembled fragments skipped)",
		len(sites), fragments)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	found := map[string]bool{}
	var problems []string
	armsUnjudged := 0
	for i, s := range sites {
		_, err := conn.Conn().Prepare(ctx, fmt.Sprintf("selectgate%d", i), s.sql)
		if err == nil {
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("%s: preparing returned a non-Postgres error: %v", s.file, err)
		}
		kind, isSchema := schemaFailure[pgErr.Code]
		if !isSchema {
			continue // syntax error from a runtime-assembled fragment
		}
		if s.arm && clauseSuppliedLater[pgErr.Code] {
			// One arm of a concatenation, failing for a clause a later arm
			// supplies. Nothing runs in this form.
			armsUnjudged++
			continue
		}

		key := fmt.Sprintf("%s: [%s] %s", s.file, pgErr.Code, pgErr.Message)
		found[key] = true
		if _, exempt := environmentDependentSelects[key]; exempt {
			continue
		}
		if _, known := knownBrokenSelects[key]; known {
			continue
		}
		one := strings.Join(strings.Fields(s.sql), " ")
		if len(one) > 160 {
			one = one[:160] + "…"
		}
		problems = append(problems, fmt.Sprintf("%s (%s)\n      %s", key, kind, one))
	}

	// Reported rather than left implicit: a gate that quietly judges less than
	// it appears to is the thing this file's header warns about.
	t.Logf("連結の一部で、後続の句が無いために判定を見送ったもの: %d件 "+
		"(GROUP BY / DISTINCT+ORDER BY 由来のみ。テーブル・列・演算子・型の"+
		"不一致は連結の一部でも判定しています)", armsUnjudged)

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("SELECT が現在のスキーマと一致しません。"+
			"実行時に 500 になるか、呼び出し側がエラーを捨てていれば空の結果として返ります: %s", p)
	}

	// Ratchet: an entry the scan no longer finds must go, so the list always
	// describes live defects rather than history.
	for key := range knownBrokenSelects {
		if !found[key] {
			t.Errorf("knownBrokenSelects still lists %q, but the scan no longer "+
				"finds it. Delete the entry.", key)
		}
	}
}

// liveSchema reads what the connected database actually has.
func liveSchema(t *testing.T, pool *pgxpool.Pool) map[string]map[string]bool {
	t.Helper()
	live := map[string]map[string]bool{}
	rows, err := pool.Query(context.Background(), `
		SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public'`)
	if err != nil {
		t.Fatalf("read live schema: %v", err)
	}
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			rows.Close()
			t.Fatalf("scan live schema: %v", err)
		}
		if live[table] == nil {
			live[table] = map[string]bool{}
		}
		live[table][col] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate live schema: %v", err)
	}
	return live
}

// schemaShortfall lists everything the migrations declare that live does not
// have. Separate from the assertion so it can be tested against a database that
// really is behind — a freshness check nobody has seen fail is a freshness
// check nobody knows works.
func schemaShortfall(declared map[string]map[string]column, live map[string]map[string]bool) []string {
	var missing []string
	for table, cols := range declared {
		lc, ok := live[table]
		if !ok {
			missing = append(missing, table)
			continue
		}
		for col := range cols {
			if !lc[col] {
				missing = append(missing, table+"."+col)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// assertSchemaMatchesMigrations stops the run if TEST_DATABASE_URL is missing
// anything the migrations declare.
func assertSchemaMatchesMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	missing := schemaShortfall(migrationSchema(t), liveSchema(t, pool))
	if len(missing) > 0 {
		shown := missing
		if len(shown) > 10 {
			shown = shown[:10]
		}
		t.Fatalf("TEST_DATABASE_URL がマイグレーションより %d 件遅れています。"+
			"このゲートは差分をコードの欠陥として報告してしまうため中断します: %v",
			len(missing), shown)
	}
}

// The freshness check must actually notice a database that is behind, or the
// gate's findings could be nothing but schema drift.
func TestTheFreshnessCheckNoticesAStaleDatabase(t *testing.T) {
	declared := map[string]map[string]column{
		"agents": {"id": {}, "hostname": {}},
		"alerts": {"id": {}},
	}

	if got := schemaShortfall(declared, map[string]map[string]bool{
		"agents": {"id": true, "hostname": true},
		"alerts": {"id": true},
	}); len(got) != 0 {
		t.Errorf("一致しているのに不足 %v が報告されました", got)
	}

	missingCol := schemaShortfall(declared, map[string]map[string]bool{
		"agents": {"id": true},
		"alerts": {"id": true},
	})
	if len(missingCol) != 1 || missingCol[0] != "agents.hostname" {
		t.Errorf("欠けている列の検出結果が %v、期待は [agents.hostname]", missingCol)
	}

	missingTable := schemaShortfall(declared, map[string]map[string]bool{
		"agents": {"id": true, "hostname": true},
	})
	if len(missingTable) != 1 || missingTable[0] != "alerts" {
		t.Errorf("欠けているテーブルの検出結果が %v、期待は [alerts]", missingTable)
	}
}

// TestTheSelectExtractorWorks stops the gate passing because the scan stopped
// matching.
func TestTheSelectExtractorWorks(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src      string
		wantSQL  bool
		fragment bool
	}{
		{"plain select", "q := `SELECT id FROM agents`", true, false},
		{"cte", "q := `WITH x AS (SELECT 1) SELECT * FROM x`", true, false},
		{"lowercase", "q := `select id from agents`", true, false},
		{"fragment", "q := `SELECT id FROM %s WHERE x=$1`", false, true},
		{"insert is not a select", "q := `INSERT INTO agents (id) VALUES ($1)`", false, false},
		{"update is not a select", "q := `UPDATE agents SET x=$1`", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := selectLiteralRe.FindStringSubmatch(tc.src)
			if m == nil {
				t.Fatal("literal extractor matched nothing")
			}
			sql := strings.TrimSpace(m[1])
			isSelect := selectStartRe.MatchString(sql)
			isFragment := isSelect && interpolationRe.MatchString(sql)
			if got := isSelect && !isFragment; got != tc.wantSQL {
				t.Errorf("checkable=%v, want %v (sql=%q)", got, tc.wantSQL, sql)
			}
			if isFragment != tc.fragment {
				t.Errorf("fragment=%v, want %v", isFragment, tc.fragment)
			}
		})
	}
}

// The two allowlists must not overlap, or an entry could go stale in one while
// the other keeps the gate green.
func TestTheSelectAllowlistsAreDisjoint(t *testing.T) {
	for key := range environmentDependentSelects {
		if _, both := knownBrokenSelects[key]; both {
			t.Errorf("%q は両方のリストにあります。環境依存なら ratchet の対象外、"+
				"欠陥なら対象です。どちらか一方にしてください", key)
		}
	}
}

// The concatenation-arm detection is load-bearing in both directions, so it is
// pinned rather than left to the gate's own pass/fail.
//
// Too lax and the gate reports a defect in a query that is never run in that
// form: internal/store/incidents.go was listed with a 42803 for four weeks,
// and the assembled statement prepares cleanly. Too strict and 45 literals stop
// being checked at all, which is a silent loss of coverage in a gate whose
// whole value is that it does not quietly cover less than it claims.
func TestConcatenationArmsAreRecognisedFromTheSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"joined immediately", "`SELECT 1`+where", true},
		{"joined after a space", "`SELECT 1` + where", true},
		{"joined after a tab", "`SELECT 1`\t+ where", true},
		{"a complete statement, comma next", "`SELECT 1`, args", false},
		{"a complete statement, paren next", "`SELECT 1`)", false},
		{"a complete statement, newline next", "`SELECT 1`\n", false},
		{"end of file", "`SELECT 1`", false},
	} {
		// The index just past the closing backtick.
		end := strings.LastIndexByte(tc.src, '`') + 1
		if got := isConcatenationArm(tc.src, end); got != tc.want {
			t.Errorf("%s: isConcatenationArm = %v, want %v (%q)",
				tc.name, got, tc.want, tc.src)
		}
	}
}

// And only the failures a later arm can explain are waived on an arm. A missing
// table does not start existing because " LIMIT 10" is appended to it.
func TestOnlyClauseFailuresAreWaivedOnAnArm(t *testing.T) {
	for code, waived := range map[string]bool{
		"42803": true,  // needs the later arm's GROUP BY
		"42P10": true,  // needs the later arm's ORDER BY
		"42P01": false, // missing table
		"42703": false, // missing column
		"42883": false, // no such operator between these types
		"22P02": false, // literal of the wrong type for the column
	} {
		if clauseSuppliedLater[code] != waived {
			t.Errorf("%s: 連結の一部での判定見送り = %v, want %v。"+
				"テーブル・列・演算子・型の不一致は、後続の句が何であろうと"+
				"欠陥です", code, clauseSuppliedLater[code], waived)
		}
	}
}

// span は [start, end) の範囲です。
type span struct{ start, end int }

// commentSpans は、その file のコメントが占める範囲を返します。
//
// 走査そのものは正規表現のままです（バッククォート文字列を拾う形は変えて
// いません）。変えたのは**コメントを除くこと**だけで、それ以外の判定は
// 同じです。
func commentSpans(src string) ([]span, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	base := fset.File(f.Pos()).Base()
	var out []span
	for _, g := range f.Comments {
		out = append(out, span{int(g.Pos()) - base, int(g.End()) - base})
	}
	return out, nil
}

func insideAny(spans []span, at int) bool {
	for _, s := range spans {
		if at >= s.start && at < s.end {
			return true
		}
	}
	return false
}

// コメントの中の SQL を拾わないこと。
//
// 緑の木では上の分岐に届かないので、合成入力で直接見ます。
func TestCommentsAreNotStatements(t *testing.T) {
	src := "package p\n\n" +
		"// この関数は `SELECT ... FROM nowhere` を投げていました。\n" +
		"const realQuery = `SELECT id FROM agents`\n"
	comments, err := commentSpans(src)
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	var kept []string
	for _, loc := range selectLiteralRe.FindAllStringSubmatchIndex(src, -1) {
		if insideAny(comments, loc[0]) {
			continue
		}
		kept = append(kept, strings.TrimSpace(src[loc[2]:loc[3]]))
	}
	if len(kept) != 1 || kept[0] != "SELECT id FROM agents" {
		t.Errorf("拾ったのは %q です。**コメントの中の一文を、直すべき"+
			"クエリとして報告していました**", kept)
	}
}
