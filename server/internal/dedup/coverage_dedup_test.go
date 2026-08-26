package dedup

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Seeds a pair of duplicate alerts and
// runs the deduplicator so its per-group merge loops execute.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping dedup coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAlertDeduplicator_Run_DB(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-dedup', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

	// Two identical alerts (same title/severity/source/agent) form a dedup group.
	for i := 0; i < 2; i++ {
		_, _ = pool.Exec(ctx,
			`INSERT INTO alerts (agent_id, severity, title, description, status, source, created_at)
			 VALUES ($1::uuid, 7, 'cov-dup-alert', 'd', 'open', 'test', NOW())`, agentID)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1", agentID) })

	// Run is an infinite ticker loop; drive the one-shot passes directly.
	d := NewAlertDeduplicator(pool)
	d.deduplicate(ctx)
	d.deduplicateByTechnique(ctx)
}
