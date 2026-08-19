package dedup

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Duplicate alerts are merged by this package, and by nothing else.
//
// scheduler.AlertAggregator claimed to do it too — wired into cmd/api, ticking
// alongside — by grouping alerts on title+agent_id and linking each duplicate
// to a parent via alerts.parent_id. No migration creates that column, and the
// worker probed for it and returned, so it never grouped anything. It has been
// deleted rather than repaired: AlertDeduplicator already merges duplicates
// using dedup_key and dedup_count, which do exist, and it does more with them
// — the aggregator would have left every duplicate open in the queue with a
// pointer to its parent, while this resolves them.
//
// That made these gates necessary. The existing DB test called both passes and
// asserted nothing, so the surviving path was unverified: deleting the dead
// worker on the grounds that this one covers the job required showing that it
// does.

func dedupPool(t *testing.T) *pgxpool.Pool {
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

// dedupFixture seeds one agent and cleans up its alerts afterwards.
func dedupFixture(t *testing.T) (*AlertDeduplicator, *pgxpool.Pool, string) {
	t.Helper()
	pool := dedupPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		VALUES ('dedup-behaviour-host', 'linux', 'online', NOW(), NOW())
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	return NewAlertDeduplicator(pool), pool, agentID
}

// seedAlert inserts one open alert, created ageSeconds ago, and returns its id.
//
// The age is explicit rather than NOW() for every row: which alert survives a
// merge is decided by created_at, and three inserts in the same millisecond
// would leave the assertion depending on clock resolution.
func seedAlert(t *testing.T, pool *pgxpool.Pool, agentID, title string, severity int,
	technique string, ageSeconds int) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO alerts (agent_id, severity, title, description, status, source,
		                    mitre_technique, created_at)
		VALUES ($1::uuid, $2, $3, 'seeded', 'open', 'test', NULLIF($4,''),
		        NOW() - make_interval(secs => $5))
		RETURNING id::text`, agentID, severity, title, technique, ageSeconds).Scan(&id); err != nil {
		t.Fatalf("seed alert %q: %v", title, err)
	}
	return id
}

// alertState reads back what the pass did to one alert.
func alertState(t *testing.T, pool *pgxpool.Pool, id string) (status, dedupKey string, dedupCount int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT status, COALESCE(dedup_key,''), COALESCE(dedup_count,0)
		FROM alerts WHERE id=$1::uuid`, id).Scan(&status, &dedupKey, &dedupCount); err != nil {
		t.Fatalf("read alert %s: %v", id, err)
	}
	return
}

// Identical alerts must be merged: the oldest kept open and marked, the rest
// resolved. This is the whole job the deleted aggregator claimed to share.
func TestIdenticalAlertsAreMergedIntoTheOldest(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	keep := seedAlert(t, pool, agentID, "dedup-identical", 7, "", 30)
	dup1 := seedAlert(t, pool, agentID, "dedup-identical", 7, "", 20)
	dup2 := seedAlert(t, pool, agentID, "dedup-identical", 7, "", 10)

	d.deduplicate(context.Background())

	keepStatus, keepKey, keepCount := alertState(t, pool, keep)
	if keepStatus != "open" {
		t.Errorf("残すべきアラートが %q になりました", keepStatus)
	}
	if keepKey == "" {
		t.Error("残したアラートに dedup_key が設定されていません")
	}
	if keepCount != 2 {
		t.Errorf("dedup_count が %d、期待は 2", keepCount)
	}

	for _, dup := range []string{dup1, dup2} {
		status, key, _ := alertState(t, pool, dup)
		if status != "resolved" {
			t.Errorf("重複アラートが %q のままです。キューに残り続けます", status)
		}
		if key != keepKey {
			t.Errorf("重複アラートの dedup_key が %q、残した側は %q", key, keepKey)
		}
	}
}

// A resolved duplicate must say which alert absorbed it, or an analyst cannot
// get back to the surviving one.
func TestAResolvedDuplicatePointsAtTheAlertThatAbsorbedIt(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	keep := seedAlert(t, pool, agentID, "dedup-pointer", 5, "", 30)
	dup := seedAlert(t, pool, agentID, "dedup-pointer", 5, "", 10)

	d.deduplicate(context.Background())

	var desc string
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(description,'') FROM alerts WHERE id=$1::uuid`, dup).Scan(&desc); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(desc, keep) {
		t.Errorf("重複アラートの説明に統合先 %s が含まれていません: %q", keep, desc)
	}
}

// Alerts that only look similar must not be merged. Dedup that is too eager
// hides real detections, which is worse than leaving duplicates.
func TestAlertsThatDifferAreNotMerged(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	a := seedAlert(t, pool, agentID, "dedup-distinct-a", 7, "", 30)
	b := seedAlert(t, pool, agentID, "dedup-distinct-b", 7, "", 20)
	// Same title, different severity — a different dedup key.
	c := seedAlert(t, pool, agentID, "dedup-distinct-a", 3, "", 10)

	d.deduplicate(context.Background())

	for _, id := range []string{a, b, c} {
		if status, _, _ := alertState(t, pool, id); status != "open" {
			t.Errorf("異なるアラート %s が %q に統合されました", id, status)
		}
	}
}

// A single alert must be left alone: there is nothing to merge it into.
func TestALoneAlertIsUntouched(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	only := seedAlert(t, pool, agentID, "dedup-lonely", 6, "", 10)

	d.deduplicate(context.Background())

	status, key, count := alertState(t, pool, only)
	if status != "open" || key != "" || count != 0 {
		t.Errorf("単独のアラートが変更されました: status=%q key=%q count=%d", status, key, count)
	}
}

// The cross-engine pass merges different titles sharing one MITRE technique,
// keeping the most severe. The title pass cannot catch these.
func TestCrossEngineDuplicatesAreMergedByTechniqueKeepingTheSeverest(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	// The severest is seeded LAST so keeping it cannot be an accident of order.
	low := seedAlert(t, pool, agentID, "PsExec Remote Execution", 4, "T1021.002", 30)
	high := seedAlert(t, pool, agentID, "PsExec Lateral Movement", 9, "T1021.002", 10)

	d.deduplicateByTechnique(context.Background())

	if status, _, _ := alertState(t, pool, high); status != "open" {
		t.Errorf("最も重大なアラートが %q になりました。残すべきです", status)
	}
	if status, key, _ := alertState(t, pool, low); status != "resolved" || key == "" {
		t.Errorf("同一テクニックの重複が統合されていません: status=%q key=%q", status, key)
	}
}

// The technique pass must not merge alerts that share a title — those are the
// title pass's job, and merging them here would skip its severity rules.
func TestTheTechniquePassIgnoresSameTitleGroups(t *testing.T) {
	d, pool, agentID := dedupFixture(t)

	a := seedAlert(t, pool, agentID, "dedup-same-title", 5, "T1059", 30)
	b := seedAlert(t, pool, agentID, "dedup-same-title", 5, "T1059", 10)

	d.deduplicateByTechnique(context.Background())

	for _, id := range []string{a, b} {
		if status, _, _ := alertState(t, pool, id); status != "open" {
			t.Errorf("同一タイトルのアラートが technique パスで統合されました: %q", status)
		}
	}
}
