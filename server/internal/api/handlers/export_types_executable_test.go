package handlers

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Two of the six export types could never produce a row.
//
// Measured against the migrated schema before this change:
//
//	process_events       MISSING   -> "processes" wrote an empty file
//	network_connections  present, but no code in this repository inserts
//	                     into it; the only writer is a test fixture
//
// The two failed differently and looked identical from outside. "processes"
// failed its existence probe and got the empty-export path; "network_connections"
// passed the probe and queried a table that is always empty. Either way the
// operator got a file with a header row and nothing under it, which reads as
// "no data in this period" rather than "this export cannot work".
//
// Both are rows of `events`, distinguished by event_type, with the payload in
// raw_data under the names internal/ingestion writes. That is where they point
// now.
//
// This gate builds and executes the real query for every export type, so a
// column name, a table name or a predicate that the schema will not accept
// fails here rather than silently producing an empty file. The existence probe
// the handler runs first is exactly what stops such a mistake from being
// noticed in production.

func exportPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// exportQueryFor builds the real query for a type over the given columns, via
// the handler's own builder. It deliberately does not reimplement it: when this
// file had its own copy, a handler that stopped applying meta.where still
// passed every test here.
func exportQueryFor(meta exportTypeMeta, columns []string) (string, []interface{}) {
	return buildExportQuery(meta, columns, time.Time{}, time.Time{}, nil, 1)
}

// Every export type must produce SQL the database accepts, over all of its
// declared columns.
func TestEveryExportTypeQueryExecutes(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	if len(exportTypes) < 5 {
		t.Fatalf("only %d export types — the map is not being read", len(exportTypes))
	}

	names := make([]string, 0, len(exportTypes))
	for name := range exportTypes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		meta := exportTypes[name]
		t.Run(name, func(t *testing.T) {
			if len(meta.allColumns) == 0 {
				t.Fatalf("エクスポート種別 %q に列が定義されていません", name)
			}
			q, args := exportQueryFor(meta, meta.allColumns)
			rows, err := pool.Query(ctx, q, args...)
			if err != nil {
				t.Fatalf("エクスポート種別 %q のクエリが実行できません: %v\nSQL: %s", name, err, q)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatalf("エクスポート種別 %q の実行時エラー: %v", name, err)
			}
		})
	}
}

// Each declared column must be individually selectable — a whole-list query
// would still pass if one column were quietly unreachable behind another.
func TestEveryExportColumnIsSelectable(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	for name, meta := range exportTypes {
		for _, col := range meta.allColumns {
			q, args := exportQueryFor(meta, []string{col})
			rows, err := pool.Query(ctx, q, args...)
			if err != nil {
				t.Errorf("%s の列 %q が取得できません: %v", name, col, err)
				continue
			}
			rows.Close()
		}
	}
}

// The two repointed types must actually return the events they claim to export.
func TestTheRepointedExportTypesReturnRows(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('export-fixture-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// The raw_data keys are the ones internal/ingestion writes.
	seed := []struct {
		eventType string
		raw       string
	}{
		{"process", `{"process_name":"evil.exe","pid":4242,"ppid":1,"command_line":"evil.exe --go","image_path":"/tmp/evil.exe","username":"root","action":"start","sha256":"abc123","md5":"def456"}`},
		{"network", `{"src_ip":"10.0.0.1","src_port":1234,"dst_ip":"203.0.113.9","dst_port":443,"protocol":"tcp","direction":"outbound","process_name":"curl","bytes_sent":10,"bytes_recv":20}`},
	}
	for _, ev := range seed {
		if _, err := pool.Exec(ctx, `
			INSERT INTO events (time, agent_id, event_type, raw_data)
			VALUES (NOW(), $1::uuid, $2, $3::jsonb)`, agentID, ev.eventType, ev.raw); err != nil {
			t.Fatalf("seed %s event: %v", ev.eventType, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
	})

	// Every column of both types, with the value the seeded event carries.
	// A projection reading a key ingestion never writes returns NULL, which
	// COALESCE turns into an empty string — no error, just a blank column, which
	// is the failure this whole file exists to catch. Checking one column per
	// type would have missed it.
	want := map[string]map[string]string{
		"processes": {
			"agent_hostname": "export-fixture-host",
			"process_name":   "evil.exe",
			"image_path":     "/tmp/evil.exe",
			"pid":            "4242",
			"ppid":           "1",
			"username":       "root",
			"command_line":   "evil.exe --go",
			"action":         "start",
			"sha256":         "abc123",
			"md5":            "def456",
		},
		"network_connections": {
			"agent_hostname": "export-fixture-host",
			"src_ip":         "10.0.0.1",
			"src_port":       "1234",
			"dst_ip":         "203.0.113.9",
			"dst_port":       "443",
			"protocol":       "tcp",
			"direction":      "outbound",
			"process_name":   "curl",
			"bytes_sent":     "10",
			"bytes_recv":     "20",
		},
	}

	for name, cols := range want {
		meta := exportTypes[name]
		t.Run(name, func(t *testing.T) {
			// Every projected column must be covered by the expectations above,
			// so adding one without a value cannot go unchecked.
			for _, col := range meta.allColumns {
				if col == "agent_id" || col == "time" {
					continue // set by the insert, not by raw_data
				}
				if _, ok := cols[col]; !ok {
					t.Errorf("列 %q に期待値がありません。射影が正しいか検証されていません", col)
				}
			}

			for col, expected := range cols {
				q, args := buildExportQuery(meta, []string{col}, time.Time{}, time.Time{},
					map[string]string{"agent_id": agentID}, 1)
				var got string
				if err := pool.QueryRow(ctx, q, args...).Scan(&got); err != nil {
					t.Errorf("%s.%s が取得できません: %v", name, col, err)
					continue
				}
				if got != expected {
					t.Errorf("%s.%s が %q、期待は %q — "+
						"射影先のキーが ingestion の書くキーと違う可能性があります",
						name, col, got, expected)
				}
			}
		})
	}
}

// The built query must actually apply the event_type predicate: without it each
// export returns the other's rows with its own columns blank.
func TestTheBuiltQueryAppliesTheEventTypePredicate(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('export-predicate-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	// Only a network event exists for this agent.
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW(), $1::uuid, 'network', '{"dst_ip":"198.51.100.7"}'::jsonb)`, agentID); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
	})

	// The processes export must not return it.
	q, args := buildExportQuery(exportTypes["processes"], []string{"process_name"},
		time.Time{}, time.Time{}, map[string]string{"agent_id": agentID}, 10)
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		t.Fatalf("processes クエリ: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if n != 0 {
		t.Errorf("プロセスのエクスポートがネットワークイベントを %d 件返しました。"+
			"event_type の絞り込みが効いていません", n)
	}
}

// The event_type predicate must actually separate the two types — without it
// each export would return the other's rows as blank columns.
func TestTheExportPredicateSeparatesEventTypes(t *testing.T) {
	for _, name := range []string{"processes", "network_connections"} {
		meta := exportTypes[name]
		if meta.where == "" {
			t.Errorf("%s に event_type の絞り込みがありません。"+
				"events 全体を返すため他種別の行が空列として混ざります", name)
		}
		if !strings.Contains(meta.where, "event_type") {
			t.Errorf("%s の絞り込みが event_type ではありません: %q", name, meta.where)
		}
	}
	if exportTypes["processes"].where == exportTypes["network_connections"].where {
		t.Error("プロセスとネットワークの絞り込みが同一です")
	}
}

// A type must not point at a table nothing writes. This is the half of the
// defect an existence probe cannot catch: network_connections existed.
func TestNoExportTypePointsAtAnUnwrittenTable(t *testing.T) {
	// Tables the repository never inserts into outside test fixtures. Keeping
	// this as a name list rather than a source scan is deliberate: the point is
	// that these two specific tables must not come back as export sources.
	unwritten := map[string]string{
		"network_connections": "no code inserts into it; the only writer is a test fixture",
		"process_events":      "no migration creates it",
		"dns_queries":         "no code inserts into it",
	}
	for name, meta := range exportTypes {
		if why, bad := unwritten[meta.table]; bad {
			t.Errorf("エクスポート種別 %q が %s を参照しています (%s)。"+
				"常に空のファイルを返します", name, meta.table, why)
		}
	}
}

// knownExportColumnMismatches records columns the export centre offers that the
// server would drop. It is empty, and that is the point: 29 entries lived here
// when the parity gate was written, every one a column an operator could tick
// and never receive. They were closed by giving each its real source — a
// differently-named column, a raw_data projection, or a join — except
// audit_logs.resource_type, which has no source anywhere in the schema and was
// removed from the page instead.
//
// The ratchet below keeps this honest in both directions: a new mismatch fails
// the gate, and an entry that stops being a mismatch must be deleted.
var knownExportColumnMismatches = map[string]bool{}

// The export centre lets an operator tick columns, and the server drops any it
// does not recognise — silently, because an unknown key is skipped rather than
// refused. Before this change the page offered `name`, `path`, `user`,
// `hash_md5`, `hash_sha256`, `started_at`, `ended_at`, `id` and
// `agent_hostname` for processes while the server whitelisted
// `process_name`, `cmdline`, `timestamp` and friends: tick every box and most
// of them never reached the file.
//
// This reads the page and requires its column ids to be a subset of the
// server's whitelist for the same type.
func TestTheExportCentreColumnsMatchTheServerWhitelist(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"frontend", "app", "admin", "export-center", "page.tsx"))
	if err != nil {
		t.Skipf("export centre page not readable: %v", err)
	}
	page := string(src)
	if len(page) < 1000 || !strings.Contains(page, "columns:") {
		t.Fatalf("エクスポートセンターのページを読めていません (%d bytes)", len(page))
	}

	// Each entry is `id: 'type',` followed by a `columns: [ { id: 'col' ... } ]`
	// block, up to the next entry.
	entryRe := regexp.MustCompile(`(?s)id:\s*'([a-z_]+)',.*?columns:\s*\[(.*?)\n\s*\],`)
	colRe := regexp.MustCompile(`\{\s*id:\s*'([a-z_0-9]+)'`)

	matches := entryRe.FindAllStringSubmatch(page, -1)
	if len(matches) < 4 {
		t.Fatalf("エクスポート種別を %d 件しか抽出できませんでした。抽出器が壊れています", len(matches))
	}

	found := map[string]bool{}
	checked := 0
	for _, m := range matches {
		typeName, block := m[1], m[2]
		meta, known := exportTypes[typeName]
		if !known {
			t.Errorf("エクスポートセンターがサーバーに存在しない種別 %q を提示しています", typeName)
			continue
		}
		allowed := make(map[string]bool, len(meta.allColumns))
		for _, c := range meta.allColumns {
			allowed[c] = true
		}
		for _, cm := range colRe.FindAllStringSubmatch(block, -1) {
			checked++
			if allowed[cm[1]] {
				continue
			}
			key := typeName + "." + cm[1]
			found[key] = true
			if !knownExportColumnMismatches[key] {
				t.Errorf("エクスポートセンターの %s が列 %q を提示していますが、"+
					"サーバーのホワイトリストに無いため黙って捨てられます", typeName, cm[1])
			}
		}
	}

	// Ratchet: a mismatch that has been fixed must leave this list, so the
	// remaining entries always describe live defects.
	for key := range knownExportColumnMismatches {
		if !found[key] {
			t.Errorf("knownExportColumnMismatches still lists %q, but the page no "+
				"longer offers it. Delete the entry.", key)
		}
	}

	if checked < 20 {
		t.Fatalf("列を %d 個しか検査していません。抽出器が壊れています", checked)
	}
}

// Columns that come from a joined table must return the joined value, not an
// empty string. A join that is present but wrong — matching nothing — produces
// exactly the blank column the whitelist mismatch produced, so the fix would
// look applied while changing nothing.
func TestJoinedExportColumnsResolve(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var groupID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agent_groups (name) VALUES ('export-join-group')
		RETURNING id::text`).Scan(&groupID); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agent_groups WHERE id=$1::uuid`, groupID)
	})

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, os_version, agent_version, status, group_id)
		VALUES ('export-join-host', 'linux', '6.1', '2.3.4', 'online', $1::uuid)
		RETURNING id::text`, groupID).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO rules (name, type, severity, content, enabled)
		VALUES ('export-join-rule', 'sigma', 3, '{}', true)
		RETURNING id::text`).Scan(&ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM rules WHERE id=$1::uuid`, ruleID)
	})

	var userID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ('export-join@example.test', 'x', 'Join Analyst', 'analyst')
		RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, userID)
	})

	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (title, severity, status, agent_id, rule_id, description,
		                    mitre_technique, assigned_to, created_at)
		VALUES ('export-join-alert', 4, 'open', $1::uuid, $2::uuid, 'joined desc',
		        'T1059', $3::uuid, NOW())`, agentID, ruleID, userID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
	})

	cases := []struct{ typeName, column, want string }{
		{"alerts", "agent_hostname", "export-join-host"},
		{"alerts", "rule_name", "export-join-rule"},
		{"alerts", "mitre_attack", "T1059"},
		{"alerts", "assignee", "export-join@example.test"},
		{"alerts", "description", "joined desc"},
		{"agents", "groups", "export-join-group"},
		{"agents", "os", "linux"},
		{"agents", "version", "2.3.4"},
		{"agents", "os_version", "6.1"},
	}
	for _, tc := range cases {
		t.Run(tc.typeName+"."+tc.column, func(t *testing.T) {
			meta := exportTypes[tc.typeName]
			filterCol := "agent_id"
			if tc.typeName == "agents" {
				filterCol = "id"
			}
			q, args := buildExportQuery(meta, []string{tc.column}, time.Time{}, time.Time{},
				map[string]string{filterCol: agentID}, 1)
			var got string
			if err := pool.QueryRow(ctx, q, args...).Scan(&got); err != nil {
				t.Fatalf("%s.%s: %v\nSQL: %s", tc.typeName, tc.column, err, q)
			}
			if got != tc.want {
				t.Errorf("%s.%s が %q、期待は %q", tc.typeName, tc.column, got, tc.want)
			}
		})
	}
}

// A joined type must not multiply its rows. A join to a table with more than
// one matching row would silently duplicate every exported record.
func TestJoinsDoNotMultiplyExportedRows(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('export-fanout-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	const want = 3
	for i := 0; i < want; i++ {
		if _, err := pool.Exec(ctx, `
			INSERT INTO events (time, agent_id, event_type, raw_data)
			VALUES (NOW(), $1::uuid, 'process', '{"process_name":"p"}'::jsonb)`, agentID); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}

	q, args := buildExportQuery(exportTypes["processes"], []string{"process_name"},
		time.Time{}, time.Time{}, map[string]string{"agent_id": agentID}, 100)
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if n != want {
		t.Errorf("%d 行返りました (期待 %d)。JOIN が行を増幅しています", n, want)
	}
}

// Joins must be outer. Most alerts carry no rule_id and many carry no
// assignee, so an inner join would drop them from the export entirely — the
// worst failure here, because a short file looks like a complete one.
func TestAlertsWithNoRuleOrAssigneeAreStillExported(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('export-bare-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// No rule_id, no assigned_to — the common shape.
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (title, severity, status, agent_id, created_at)
		VALUES ('bare-alert', 3, 'open', $1::uuid, NOW())`, agentID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	for _, col := range []string{"title", "rule_name", "assignee", "agent_hostname"} {
		t.Run(col, func(t *testing.T) {
			q, args := buildExportQuery(exportTypes["alerts"], []string{col},
				time.Time{}, time.Time{}, map[string]string{"agent_id": agentID}, 10)
			rows, err := pool.Query(ctx, q, args...)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			defer rows.Close()
			n := 0
			for rows.Next() {
				n++
			}
			if n != 1 {
				t.Errorf("rule/assignee の無いアラートが %d 行になりました (期待 1)。"+
					"内部結合になっていると行ごと落ちます", n)
			}
		})
	}

	// An agent with no group must still export.
	q, args := buildExportQuery(exportTypes["agents"], []string{"hostname", "groups"},
		time.Time{}, time.Time{}, map[string]string{"id": agentID}, 10)
	var hostname, group string
	if err := pool.QueryRow(ctx, q, args...).Scan(&hostname, &group); err != nil {
		t.Fatalf("グループ未所属のエージェントがエクスポートされません: %v", err)
	}
	if hostname != "export-bare-host" {
		t.Errorf("hostname が %q", hostname)
	}
	if group != "" {
		t.Errorf("グループ未所属なのに %q が返りました", group)
	}
}

// The events export projects several columns out of raw_data. Those are the
// same shape of mistake as the repointed types: a key ingestion does not write
// yields NULL, COALESCE turns it into an empty string, and the query still
// executes. Checking the SQL runs is not enough — the values have to come back.
func TestTheEventsExportProjectionsReturnTheirValues(t *testing.T) {
	pool := exportPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('export-events-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// Written with the keys internal/ingestion emits for a process event.
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, severity, raw_data)
		VALUES (NOW(), $1::uuid, 'process', 4,
		        '{"process_name":"proj.exe","image_path":"/opt/proj.exe","pid":777,"username":"svc"}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	meta := exportTypes["events"]
	want := map[string]string{
		"process_name":   "proj.exe",
		"process_path":   "/opt/proj.exe",
		"pid":            "777",
		"user":           "svc",
		"agent_hostname": "export-events-host",
		"event_type":     "process",
		"severity":       "4",
	}

	// Every raw_data projection this type declares must have an expectation, so
	// adding one without checking its key cannot slip through.
	for col, expr := range meta.columnExpr {
		if !strings.Contains(expr, "raw_data->>") {
			continue
		}
		if _, ok := want[col]; !ok {
			t.Errorf("events の射影列 %q に期待値がありません (%s)", col, expr)
		}
	}

	for col, expected := range want {
		q, args := buildExportQuery(meta, []string{col}, time.Time{}, time.Time{},
			map[string]string{"agent_id": agentID, "event_type": "process"}, 1)
		var got string
		if err := pool.QueryRow(ctx, q, args...).Scan(&got); err != nil {
			t.Errorf("events.%s が取得できません: %v", col, err)
			continue
		}
		if got != expected {
			t.Errorf("events.%s が %q、期待は %q — "+
				"射影先のキーが ingestion の書くキーと違う可能性があります", col, got, expected)
		}
	}
}
