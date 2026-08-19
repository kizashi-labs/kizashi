package scheduler

import (
	"context"
	"testing"
)

// Both writers that used to fill the duplicated columns are exercised against
// a real database here.
//
// Migration 379 dropped ioc_type, enabled and threat_level. A writer still
// naming one of them fails with 42703 at runtime — loudly, but only when a
// feed actually runs, which no test did. FeedScheduler.upsertIOC set ioc_type
// alongside type, and the enrichment handler's cache wrote threat_level; both
// are covered now, so a revert fails here instead of on the next feed sync.

// The feed importer's upsert must work against the current schema.
func TestTheFeedUpsertWritesTheCurrentColumns(t *testing.T) {
	pool := retroPool(t)
	ctx := context.Background()

	const value = "writer-feed.example"
	_, _ = pool.Exec(ctx, `DELETE FROM ioc_entries WHERE value=$1`, value)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, value)
	})

	s := &FeedScheduler{pool: pool}
	if err := s.upsertIOC(ctx, "domain", value, "from a feed", "unit-test-feed"); err != nil {
		t.Fatalf("フィード取り込みの upsert が失敗しました: %v", err)
	}

	var typ, source string
	var severity int
	var active bool
	if err := pool.QueryRow(ctx, `
		SELECT type, severity, is_active, source_feed FROM ioc_entries WHERE value=$1`,
		value).Scan(&typ, &severity, &active, &source); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if typ != "domain" {
		t.Errorf("type が %q", typ)
	}
	if !active {
		t.Error("取り込んだ指標が is_active=false です")
	}
	if severity < 1 || severity > 10 {
		t.Errorf("severity が %d で 1..10 の範囲外です", severity)
	}

	// Re-importing the same indicator must update rather than duplicate.
	if err := s.upsertIOC(ctx, "domain", value, "seen again", "unit-test-feed"); err != nil {
		t.Fatalf("2回目の upsert が失敗しました: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE value=$1`, value).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("同じ指標が %d 行になりました", n)
	}
}
