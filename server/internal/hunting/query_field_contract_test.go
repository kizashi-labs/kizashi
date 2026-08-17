package hunting

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Four of the fourteen hunting fields could never match anything.
//
// buildSQL mapped each hunting field to a raw_data key, and four of those keys
// have never been written by the ingestion path. Verified by running the real
// normaliser (ingestion.normalizeEventData) over one event of each type and
// reading the keys it emits:
//
//	dns      -> answers pid process_name query query_type
//	process  -> action command_line image_path md5 pid ppid process_name
//	            sha256 username
//	file     -> file_size old_path operation path pid process_name sha256
//	network  -> bytes_recv bytes_sent direction dst_ip dst_port pid
//	            process_name protocol src_ip src_port state
//
//	cmdline    -> raw_data->>'cmdline'     never written (command_line)
//	file_path  -> raw_data->>'file_path'   never written (path)
//	domain     -> raw_data->>'domain'      never written (query)
//	hash       -> raw_data->>'hash'        never written (sha256/md5/sha1)
//
// A JSONB lookup on an absent key is NULL, not an error, so each of these
// hunts returned zero rows and looked like a clean result. They are also the
// four pivots a hunt actually starts from: a command line, a file path, a
// domain, a hash.
//
// This gate seeds one event per type with exactly what ingestion writes and
// requires every hunting field to find it. A mapping that names a key nothing
// writes fails here instead of answering an analyst with silence.

func huntPool(t *testing.T) *pgxpool.Pool {
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

// The raw_data of each seeded event, written with the keys the normaliser
// emits — not the keys the hunting engine used to look for.
const (
	rawProcess = `{"process_name":"evil.exe","command_line":"evil.exe --steal",` +
		`"image_path":"/tmp/evil.exe","username":"root","pid":4242,"ppid":1,` +
		`"action":"create","sha256":"aaaa1111","md5":"bbbb2222"}`
	rawDNS     = `{"query":"c2.evil.example","query_type":"A","process_name":"curl"}`
	rawNetwork = `{"src_ip":"10.0.0.9","dst_ip":"203.0.113.77","dst_port":"8443",` +
		`"protocol":"tcp","direction":"outbound"}`
	rawFile = `{"path":"/etc/shadow","operation":"write","sha1":"cccc3333"}`
)

// huntFixture seeds one agent and one event of each type, returning an engine
// and the agent id every query filters on.
func huntFixture(t *testing.T) (*Engine, string) {
	t.Helper()
	pool := huntPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('hunt-field-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	for _, ev := range []struct{ eventType, raw string }{
		{"process", rawProcess},
		{"dns", rawDNS},
		{"network", rawNetwork},
		{"file", rawFile},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO events (time, agent_id, event_type, severity, raw_data)
			VALUES (NOW(), $1::uuid, $2, 5, $3::jsonb)`,
			agentID, ev.eventType, ev.raw); err != nil {
			t.Fatalf("seed %s event: %v", ev.eventType, err)
		}
	}

	return NewEngine(pool), agentID
}

// hunt runs a query filtered to the fixture agent plus one extra filter.
func hunt(t *testing.T, e *Engine, agentID string, f QueryFilter) int {
	t.Helper()
	res, err := e.Execute(context.Background(), &HuntingQuery{
		Filters: []QueryFilter{
			{Field: "agent_id", Operator: "eq", Value: agentID},
			f,
		},
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("hunt %s %s %q: %v", f.Field, f.Operator, f.Value, err)
	}
	return len(res.Results)
}

// Every hunting field must find the event carrying its value. The four that
// were broken are marked; the rest guard against a fix breaking them.
func TestEveryHuntingFieldFindsTheEventItNames(t *testing.T) {
	e, agentID := huntFixture(t)

	cases := []struct {
		field, value string
		wasBroken    bool
	}{
		{field: "process_name", value: "evil.exe"},
		{field: "username", value: "root"},
		{field: "src_ip", value: "10.0.0.9"},
		{field: "dst_ip", value: "203.0.113.77"},
		{field: "dst_port", value: "8443"},
		{field: "event_type", value: "process"},

		{field: "cmdline", value: "evil.exe --steal", wasBroken: true},
		{field: "file_path", value: "/etc/shadow", wasBroken: true},
		{field: "domain", value: "c2.evil.example", wasBroken: true},
		{field: "hash", value: "aaaa1111", wasBroken: true},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			if n := hunt(t, e, agentID, QueryFilter{
				Field: tc.field, Operator: "eq", Value: tc.value,
			}); n == 0 {
				msg := "ハンティングフィールド %q が値 %q のイベントを見つけられません"
				if tc.wasBroken {
					msg += " — ingestion が書かないキーを参照している症状です"
				}
				t.Errorf(msg, tc.field, tc.value)
			}
		})
	}
}

// A hash hunt must hit whichever digest the agent captured. The process event
// carries sha256 and md5; the file event carries sha1 only.
func TestAHashHuntMatchesAnyDigest(t *testing.T) {
	e, agentID := huntFixture(t)

	for _, digest := range []struct{ name, value string }{
		{"sha256", "aaaa1111"},
		{"md5", "bbbb2222"},
		{"sha1", "cccc3333"},
	} {
		t.Run(digest.name, func(t *testing.T) {
			if n := hunt(t, e, agentID, QueryFilter{
				Field: "hash", Operator: "eq", Value: digest.value,
			}); n == 0 {
				t.Errorf("%s のハッシュ %q が一致しません。"+
					"エージェントが取得したダイジェスト種別に関わらず一致する必要があります",
					digest.name, digest.value)
			}
		})
	}
}

// Negating a multi-candidate field must mean "none of the digests match".
// ORing the candidates would let the process event satisfy hash != aaaa1111
// merely because its md5 differs from it.
func TestNegatingAHashExcludesTheEventCarryingIt(t *testing.T) {
	e, agentID := huntFixture(t)

	// The process event holds sha256 aaaa1111 and md5 bbbb2222.
	total := hunt(t, e, agentID, QueryFilter{Field: "event_type", Operator: "eq", Value: "process"})
	if total == 0 {
		t.Fatal("プロセスイベントが見つかりません")
	}

	res, err := e.Execute(context.Background(), &HuntingQuery{
		Filters: []QueryFilter{
			{Field: "agent_id", Operator: "eq", Value: agentID},
			{Field: "event_type", Operator: "eq", Value: "process"},
			{Field: "hash", Operator: "neq", Value: "aaaa1111"},
		},
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if len(res.Results) != 0 {
		t.Errorf("hash != aaaa1111 が、そのsha256を持つイベントを %d 件返しました。"+
			"否定は全候補について成立する必要があります", len(res.Results))
	}
}

// contains must work on the repointed fields too, not just equality.
func TestContainsWorksOnTheRepointedFields(t *testing.T) {
	e, agentID := huntFixture(t)

	for _, tc := range []struct{ field, fragment string }{
		{"cmdline", "--steal"},
		{"file_path", "shadow"},
		{"domain", "evil.example"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if n := hunt(t, e, agentID, QueryFilter{
				Field: tc.field, Operator: "contains", Value: tc.fragment,
			}); n == 0 {
				t.Errorf("%s の contains 検索が %q を見つけられません", tc.field, tc.fragment)
			}
		})
	}
}

// An unknown field is still skipped rather than interpolated — the whitelist is
// what keeps this query builder injection-safe.
func TestAnUnknownFieldIsStillIgnored(t *testing.T) {
	e, agentID := huntFixture(t)

	// If the field were interpolated, this would be a syntax error rather than
	// a query that simply ignores the filter.
	n := hunt(t, e, agentID, QueryFilter{
		Field: "e.time) --", Operator: "eq", Value: "x",
	})
	if n == 0 {
		t.Error("未知のフィールドはフィルタごと無視されるべきです")
	}
}

// A field must not be findable under a key ingestion does not write. This pins
// the direction of the fix: repointing cmdline at command_line must not leave
// the old key working, because nothing would then notice a future regression.
func TestTheOldKeysAreNotStillConsulted(t *testing.T) {
	e, agentID := huntFixture(t)
	ctx := context.Background()

	// An event written with the OLD key names only.
	pool := huntPool(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, severity, raw_data)
		VALUES (NOW(), $1::uuid, 'process', 5,
		        '{"cmdline":"old-key-only","file_path":"/old/key","domain":"old.key","hash":"oldhash"}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed legacy event: %v", err)
	}

	for _, tc := range []struct{ field, value string }{
		{"cmdline", "old-key-only"},
		{"file_path", "/old/key"},
		{"domain", "old.key"},
		{"hash", "oldhash"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if n := hunt(t, e, agentID, QueryFilter{
				Field: tc.field, Operator: "eq", Value: tc.value,
			}); n != 0 {
				t.Errorf("%s が旧キーの値 %q を見つけました。"+
					"ingestion が書かないキーを参照し続けています", tc.field, tc.value)
			}
		})
	}
}

// An operator the builder does not implement must drop the filter, not quietly
// become equality. A hunt asking for "startswith" and silently receiving exact
// matches is answered wrongly rather than refused.
func TestAnUnsupportedOperatorDropsTheFilterRatherThanGuessing(t *testing.T) {
	e, agentID := huntFixture(t)

	all := hunt(t, e, agentID, QueryFilter{
		Field: "event_type", Operator: "eq", Value: "process",
	})
	if all == 0 {
		t.Fatal("プロセスイベントが見つかりません")
	}

	// "startswith" is not implemented. The filter must be ignored, so this sees
	// every event of the agent — more than the single process event an
	// equality match on process_name would return.
	total := hunt(t, e, agentID, QueryFilter{
		Field: "process_name", Operator: "startswith", Value: "evil.exe",
	})
	if total <= all {
		t.Errorf("未対応の演算子が等価比較として扱われた可能性があります "+
			"(件数 %d、プロセスイベントのみは %d)", total, all)
	}
}
