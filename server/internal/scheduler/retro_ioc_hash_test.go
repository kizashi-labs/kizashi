package scheduler

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hash IOCs were hunted by nothing.
//
// scheduler.IOCMatcher claimed to compare every process against the IOC list
// once a minute, and was wired into cmd/api. Measured against the migrated
// schema, its two halves read:
//
//	process_events       MISSING   -> no hash was ever compared
//	network_connections  present, but no code inserts into it
//
// so neither half could match anything. detection.IOCMatcher covers hashes on
// live events in cmd/detection, which left history uncovered: RetroIOCHunter,
// the component whose whole purpose is "historical events × newly-added IOCs",
// hunted only ip and domain. A malware hash added by a feed today therefore
// never surfaced yesterday's execution — the exact case retroactive hunting
// exists for.
//
// These gates pin that a hash IOC now matches a historical process event, and
// that it does so under each hash key and event type the ingestion path writes.

func retroPool(t *testing.T) *pgxpool.Pool {
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

// retroFixture seeds one agent and returns a hunter plus the agent id.
func retroFixture(t *testing.T) (*RetroIOCHunter, *pgxpool.Pool, string) {
	t.Helper()
	pool := retroPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('retro-hash-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	return NewRetroIOCHunter(pool, nil, 30, time.Hour), pool, agentID
}

// seedEvent inserts one historical event carrying the given raw_data.
func seedEvent(t *testing.T, pool *pgxpool.Pool, agentID, eventType, raw string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW() - INTERVAL '2 days', $1::uuid, $2, $3::jsonb)`,
		agentID, eventType, raw); err != nil {
		t.Fatalf("seed %s event: %v", eventType, err)
	}
}

// A hash IOC must match a process event that already happened.
func TestAHashIOCMatchesAHistoricalProcessEvent(t *testing.T) {
	h, pool, agentID := retroFixture(t)
	const hash = "e3b0c44298fc1c149afbf4c8996fb924"

	seedEvent(t, pool, agentID, "process",
		`{"process_name":"evil.exe","sha256":"`+hash+`"}`)

	iocs := iocMeta{hash: 4}
	n, _ := h.huntField(context.Background(), "process", "sha256", true, iocs, ipDomainThreat(iocs))
	if n == 0 {
		t.Fatal("ハッシュIOCが過去のプロセスイベントに一致しませんでした。" +
			"これが scheduler.IOCMatcher が存在しないテーブルを見ていたときの症状です")
	}
}

// Case must not decide whether a hash matches: feeds and agents disagree.
func TestHashMatchingIsCaseInsensitive(t *testing.T) {
	h, pool, agentID := retroFixture(t)

	seedEvent(t, pool, agentID, "process",
		`{"process_name":"evil.exe","sha256":"AABBCCDDEEFF0011"}`)

	// The loader lowercases IOC values, so that is what huntField receives.
	iocs := iocMeta{"aabbccddeeff0011": 4}
	if n, _ := h.huntField(context.Background(), "process", "sha256", true, iocs, ipDomainThreat(iocs)); n == 0 {
		t.Error("大文字のハッシュを含むイベントに小文字のIOCが一致しませんでした")
	}
}

// Every hash key and event type the ingestion path writes must be covered.
func TestEveryHashKeyAndEventTypeIsHunted(t *testing.T) {
	// addHashes writes sha256/md5/sha1, and it is called for process, file and
	// image_load events.
	for _, eventType := range []string{"process", "file", "image_load"} {
		for _, field := range []string{"sha256", "md5", "sha1"} {
			t.Run(eventType+"/"+field, func(t *testing.T) {
				h, pool, agentID := retroFixture(t)
				hash := "deadbeef" + eventType + field

				seedEvent(t, pool, agentID, eventType,
					`{"process_name":"x","`+field+`":"`+hash+`"}`)

				iocs := iocMeta{hash: 3}
				if n, _ := h.huntField(context.Background(), eventType, field, true, iocs, ipDomainThreat(iocs)); n == 0 {
					t.Errorf("%s イベントの %s が照合されていません", eventType, field)
				}
			})
		}
	}
}

// The loader must route hash IOCs to the hash bucket, under every spelling
// ioc_entries uses, and must not put them in the ip or domain buckets.
func TestTheLoaderRoutesEachTypeToItsBucket(t *testing.T) {
	h, pool, _ := retroFixture(t)
	ctx := context.Background()

	// `type` is CHECK-constrained to hash|ip|domain|url|email, and it is what
	// the loader reads. There is no per-digest spelling to route any more:
	// migration 379 dropped ioc_type, which was the only column that carried
	// md5/sha1/sha256 as distinct values.
	seeded := map[string]string{
		"hash":   "1111111111111111",
		"ip":     "198.51.100.23",
		"domain": "retro-hash.example",
		"url":    "http://retro-hash.example/x",
		"email":  "retro@hash.example",
	}
	for typ, value := range seeded {
		if _, err := pool.Exec(ctx, `
			INSERT INTO ioc_entries (type, value, is_active, first_seen, severity)
			VALUES ($1, $2, true, NOW(), 4)`, typ, value); err != nil {
			t.Fatalf("seed ioc %s: %v", typ, err)
		}
	}
	t.Cleanup(func() {
		for _, value := range seeded {
			_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, value)
		}
	})

	ips, domains, hashes, _ := h.loadNewIOCs(ctx, time.Now().Add(-time.Hour))

	if _, ok := hashes[seeded["hash"]]; !ok {
		t.Error("hash が読み込まれていません")
	}
	if _, ok := ips[seeded["ip"]]; !ok {
		t.Error("ip が読み込まれていません")
	}
	if _, ok := domains[seeded["domain"]]; !ok {
		t.Error("domain が読み込まれていません")
	}
	// Each bucket takes only its own type: a url or an email must not be
	// hunted as a domain, which would match unrelated DNS traffic.
	for _, stray := range []string{seeded["url"], seeded["email"]} {
		if _, ok := domains[stray]; ok {
			t.Errorf("%q がドメインとして読み込まれました", stray)
		}
		if _, ok := ips[stray]; ok {
			t.Errorf("%q がIPとして読み込まれました", stray)
		}
		if _, ok := hashes[stray]; ok {
			t.Errorf("%q がハッシュとして読み込まれました", stray)
		}
	}
	// And nothing lands in more than one bucket.
	for _, v := range []string{seeded["hash"], seeded["ip"], seeded["domain"]} {
		n := 0
		for _, bucket := range []iocMeta{ips, domains, hashes} {
			if _, ok := bucket[v]; ok {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q が %d 個のバケットに入りました", v, n)
		}
	}
}

// The dst_ip hunt must stay case-sensitive-as-is: folding an address is
// harmless but the flag must reach the query, so a regression that folds
// everything or nothing is visible.
func TestIPHuntingDoesNotFoldCase(t *testing.T) {
	h, pool, agentID := retroFixture(t)

	seedEvent(t, pool, agentID, "network", `{"dst_ip":"203.0.113.55"}`)

	iocs := iocMeta{"203.0.113.55": 4}
	if n, _ := h.huntField(context.Background(), "network", "dst_ip", false, iocs, ipDomainThreat(iocs)); n == 0 {
		t.Error("IP IOC が過去のネットワークイベントに一致しませんでした")
	}
}

// A domain hunt must still fold case, as it did before hashes were added.
func TestDomainHuntingStillFoldsCase(t *testing.T) {
	h, pool, agentID := retroFixture(t)

	seedEvent(t, pool, agentID, "dns", `{"query":"EVIL.Example.COM"}`)

	iocs := iocMeta{"evil.example.com": 4}
	if n, _ := h.huntField(context.Background(), "dns", "query", true, iocs, ipDomainThreat(iocs)); n == 0 {
		t.Error("大文字を含むDNSクエリに小文字のドメインIOCが一致しませんでした")
	}
}

// The tests above drive huntField directly, which cannot see what hunt()
// decides to hunt: which event types, which hash keys, and whether a pass runs
// at all when only hashes are new. These drive hunt() end to end.

// huntFixture prepares a hunt() run: an agent, a rewound watermark, and cleanup
// that restores the watermark so concurrent packages are unaffected.
func huntFixture(t *testing.T) (*RetroIOCHunter, *pgxpool.Pool, string) {
	t.Helper()
	h, pool, agentID := retroFixture(t)
	ctx := context.Background()

	var saved time.Time
	if err := pool.QueryRow(ctx,
		`SELECT last_hunted_at FROM ioc_hunt_state WHERE id = 1`).Scan(&saved); err != nil {
		t.Skipf("ioc_hunt_state unavailable: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE ioc_hunt_state SET last_hunted_at = NOW() - INTERVAL '1 hour' WHERE id = 1`); err != nil {
		t.Fatalf("rewind watermark: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`UPDATE ioc_hunt_state SET last_hunted_at = $1 WHERE id = 1`, saved)
	})
	return h, pool, agentID
}

// seedHashIOC registers one hash IOC. The stored value is deliberately
// UPPERCASE: the loader must fold it, since feeds and agents disagree on case.
func seedHashIOC(t *testing.T, pool *pgxpool.Pool, value string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ioc_entries (type, value, is_active, first_seen, severity)
		VALUES ('hash', $1, true, NOW(), 4)`, strings.ToUpper(value)); err != nil {
		t.Fatalf("seed hash ioc: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value = $1`, strings.ToUpper(value))
	})
}

// retroAlertCount counts retro alerts raised for one agent.
func retroAlertCount(t *testing.T, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM alerts WHERE agent_id = $1::uuid AND source = 'retro_ioc'`,
		agentID).Scan(&n); err != nil {
		t.Fatalf("count retro alerts: %v", err)
	}
	return n
}

// A full pass must raise an alert for a historical process execution whose
// hash a feed registered afterwards. Hashes are the only new IOCs here, so this
// also pins that a hash-only batch is not skipped by the early return.
func TestAFullHuntAlertsOnAHistoricalHashMatch(t *testing.T) {
	h, pool, agentID := huntFixture(t)
	const hash = "9f86d081884c7d659a2feaa0c55ad015"

	seedEvent(t, pool, agentID, "process", `{"process_name":"evil.exe","sha256":"`+hash+`"}`)
	seedHashIOC(t, pool, hash)

	h.hunt(context.Background())

	if retroAlertCount(t, pool, agentID) == 0 {
		t.Fatal("ハッシュIOCの遡及照合でアラートが作成されませんでした。" +
			"ハッシュは以前どのコンポーネントからも照合されていませんでした")
	}
}

// Each hash key and event type must be reached by the pass itself, not merely
// by huntField when called with the right arguments.
func TestAFullHuntCoversEachHashKeyAndEventType(t *testing.T) {
	cases := []struct{ eventType, field string }{
		{"process", "sha256"},
		{"process", "md5"},
		{"process", "sha1"},
		{"file", "sha256"},
		{"image_load", "sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.eventType+"/"+tc.field, func(t *testing.T) {
			h, pool, agentID := huntFixture(t)
			hash := "abcdef0123456789" + tc.eventType[:3] + tc.field

			seedEvent(t, pool, agentID, tc.eventType, `{"`+tc.field+`":"`+hash+`"}`)
			seedHashIOC(t, pool, hash)

			h.hunt(context.Background())

			if retroAlertCount(t, pool, agentID) == 0 {
				t.Errorf("%s イベントの %s が遡及照合の対象になっていません", tc.eventType, tc.field)
			}
		})
	}
}

// An empty IOC set must find nothing rather than matching every event.
func TestHuntingWithNoIOCsFindsNothing(t *testing.T) {
	h, pool, agentID := retroFixture(t)

	seedEvent(t, pool, agentID, "process", `{"sha256":"1234567890abcdef"}`)

	if n, _ := h.huntField(context.Background(), "process", "sha256", true, iocMeta{}, iocMeta{}); n != 0 {
		t.Errorf("IOCが無いのに %d 件一致しました", n)
	}
}

// IP IOCs are stored without folding, so the query side must not fold either.
// IPv4 has no case, but an IPv6 IOC written in uppercase hex does: folding one
// side only would stop it matching.
func TestAnUppercaseIPv6IOCStillMatches(t *testing.T) {
	h, pool, agentID := retroFixture(t)
	const addr = "2001:DB8::BEEF"

	seedEvent(t, pool, agentID, "network", `{"dst_ip":"`+addr+`"}`)

	// loadNewIOCs stores ip values unfolded, so this is what huntField receives.
	iocs := iocMeta{addr: 4}
	if n, _ := h.huntField(context.Background(), "network", "dst_ip", false, iocs, ipDomainThreat(iocs)); n == 0 {
		t.Error("大文字のIPv6 IOCが一致しませんでした。" +
			"IOC側を畳まずクエリ側だけを畳むと一致しなくなります")
	}
}

// ─── IOC vocabulary ──────────────────────────────────────────────────────────
//
// ioc_entries carries three duplicated pairs — type/ioc_type,
// is_active/enabled, severity/threat_level — and this component read the wrong
// half of each. cmd/detection's ListActiveIOCs, which drives live matching,
// reads type, is_active and severity; retroactive hunting read ioc_type,
// enabled and threat_level.
//
// Measured before the change:
//
//	well-formed IOC alone                          -> domains=1
//	one NULL-ioc_type row ahead of it by first_seen -> domains=0
//
// ioc_type is nullable and 4 of the 6 writers never set it, including manual
// adds and the TAXII and STIX importers. A NULL fails the Scan, and pgx ends
// iteration on a scan error, so one manually added indicator did not skip
// itself — it aborted the batch and everything ordered after it.

// seedIOC inserts an indicator the way a given writer does.
func seedIOC(t *testing.T, pool *pgxpool.Pool, opts iocSeed) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ioc_entries (type, value, description, severity, is_active, first_seen)
		VALUES ($1, $2, 'seeded', $3, $4, NOW() - make_interval(secs => $5))`,
		opts.typ, opts.value, opts.severity, opts.isActive, opts.ageSeconds,
	); err != nil {
		t.Fatalf("seed ioc %q: %v", opts.value, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, opts.value)
	})
}

type iocSeed struct {
	typ        string
	value      string
	severity   int
	isActive   bool
	ageSeconds int
}

// An indicator added by hand, or imported over TAXII or STIX, must be hunted.
// Those paths set only type, value, description, severity and is_active —
// which is now every column the loader needs, since migration 379 dropped the
// optional ioc_type that used to decide whether an indicator was visible here.
func TestAMinimallyPopulatedIOCIsStillHunted(t *testing.T) {
	h, pool, _ := retroFixture(t)

	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-manual.example",
		severity: 9, isActive: true, ageSeconds: 10})

	_, domains, _, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))
	if _, ok := domains["vocab-manual.example"]; !ok {
		t.Error("最小限の列しか持たない指標が読み込まれていません。" +
			"手動追加・TAXII・STIX 経由の指標はすべてこの形です")
	}
}

// A batch must survive its first row whatever that row looks like. The
// original failure was a NULL ioc_type: it failed the Scan, pgx ends iteration
// on a scan error, and one manually-added indicator therefore took every IOC
// ordered after it down with it. Dropping the column removed the NULL, and the
// loader reads only NOT NULL columns now — this holds that property.
func TestOneOddIOCDoesNotAbortTheBatch(t *testing.T) {
	h, pool, _ := retroFixture(t)

	// Ordered first by first_seen, so it is scanned before the others.
	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-null.example",
		severity: 5, isActive: true, ageSeconds: 300})
	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-good.example",
		severity: 5, isActive: true, ageSeconds: 10})
	seedIOC(t, pool, iocSeed{typ: "ip", value: "198.51.100.99",
		severity: 5, isActive: true, ageSeconds: 10})

	ips, domains, _, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))
	if _, ok := domains["vocab-good.example"]; !ok {
		t.Error("先行する1件の不正な行でバッチ全体が打ち切られています")
	}
	if _, ok := ips["198.51.100.99"]; !ok {
		t.Error("先行する1件の不正な行で以降のIOCが読み込まれていません")
	}
}

// Deactivating an indicator must stop it being hunted. store.SetActive clears
// is_active, which is the only such flag now.
func TestADeactivatedIOCIsNotHunted(t *testing.T) {
	h, pool, _ := retroFixture(t)

	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-off.example",
		severity: 9, isActive: false, ageSeconds: 10})

	_, domains, _, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))
	if _, ok := domains["vocab-off.example"]; ok {
		t.Error("無効化した指標が依然として遡及照合の対象です。" +
			"APIの無効化は is_active を落としますが、ここは enabled を見ていました")
	}
}

// is_active is what decides, matching live matching. Pinning both directions
// keeps the two readers from drifting apart again.
func TestIsActiveIsWhatDecidesWhichIOCsAreHunted(t *testing.T) {
	h, pool, _ := retroFixture(t)

	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-active.example",
		severity: 5, isActive: true, ageSeconds: 10})
	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-inactive.example",
		severity: 5, isActive: false, ageSeconds: 10})

	_, domains, _, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))
	if _, ok := domains["vocab-active.example"]; !ok {
		t.Error("is_active=true の指標が読み込まれていません")
	}
	if _, ok := domains["vocab-inactive.example"]; ok {
		t.Error("is_active=false の指標が読み込まれています")
	}
}

// The severity a feed set must reach the alert, rather than threat_level's
// default. A critical indicator has to be able to raise a critical alert.
func TestTheAlertSeverityComesFromTheIOCsSeverity(t *testing.T) {
	h, pool, _ := retroFixture(t)

	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-critical.example",
		severity: 9, isActive: true, ageSeconds: 10})

	_, domains, _, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))
	got, ok := domains["vocab-critical.example"]
	if !ok {
		t.Fatal("指標が読み込まれていません")
	}
	if got != 9 {
		t.Errorf("読み込まれた深刻度が %d、期待は 9 — "+
			"threat_level の既定値ではなくフィードが設定した severity を使う必要があります", got)
	}
}

// The alert scale is the alerts table's 1..10, not a clamp at 5.
func TestARetroAlertCanExceedSeverityFive(t *testing.T) {
	h, pool, agentID := huntFixture(t)

	seedEvent(t, pool, agentID, "dns", `{"query":"vocab-sev.example"}`)
	seedIOC(t, pool, iocSeed{typ: "domain", value: "vocab-sev.example",
		severity: 9, isActive: true, ageSeconds: 10})

	h.hunt(context.Background())

	var sev int
	if err := pool.QueryRow(context.Background(),
		`SELECT severity FROM alerts WHERE agent_id=$1::uuid AND source='retro_ioc'
		 ORDER BY created_at DESC LIMIT 1`, agentID).Scan(&sev); err != nil {
		t.Fatalf("遡及アラートが作成されていません: %v", err)
	}
	if sev != 9 {
		t.Errorf("アラートの深刻度が %d、期待は 9。"+
			"alerts.severity は 1..10 で、5 で頭打ちにする理由はありません", sev)
	}
}

// The loader must fold domain and hash keys as it reads them. Events are
// matched with LOWER() applied to the column, so an indicator a feed delivered
// in upper case would never match unless the key side is folded too.
func TestTheLoaderFoldsDomainAndHashKeys(t *testing.T) {
	h, pool, _ := retroFixture(t)

	seedIOC(t, pool, iocSeed{typ: "domain", value: "VOCAB-UPPER.Example",
		severity: 5, isActive: true, ageSeconds: 10})
	seedIOC(t, pool, iocSeed{typ: "hash", value: "AABBCCDD11223344",
		severity: 5, isActive: true, ageSeconds: 10})
	// An IP must NOT be folded: the key and the query side are both raw.
	seedIOC(t, pool, iocSeed{typ: "ip", value: "2001:DB8::5",
		severity: 5, isActive: true, ageSeconds: 10})

	ips, domains, hashes, _ := h.loadNewIOCs(context.Background(), time.Now().Add(-time.Hour))

	if _, ok := domains["vocab-upper.example"]; !ok {
		t.Errorf("大文字のドメイン指標が小文字化されていません: %v", keysOf(domains))
	}
	if _, ok := hashes["aabbccdd11223344"]; !ok {
		t.Errorf("大文字のハッシュ指標が小文字化されていません: %v", keysOf(hashes))
	}
	if _, ok := ips["2001:DB8::5"]; !ok {
		t.Errorf("IP指標が加工されています: %v", keysOf(ips))
	}
}

// keysOf lists a bucket's keys for failure messages.
func keysOf(m iocMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
