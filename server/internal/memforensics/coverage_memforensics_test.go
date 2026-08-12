package memforensics

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the DB-backed injection/reflective
// detectors and the artifact/stats readers against a seeded process event.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping memforensics coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAnalyzer_DetectAndStats_DB(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-mem', 'windows', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })
	_, _ = pool.Exec(ctx,
		`INSERT INTO events (agent_id, event_type, raw_data, time)
		 VALUES ($1::uuid, 'process',
		   '{"process_name":"lsass.exe","command_line":"c","memory_protection":"RWX","hostname":"cov-mem"}'::jsonb, NOW())`,
		agentID)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM events WHERE agent_id=$1", agentID) })

	a := NewAnalyzer(pool)
	if _, err := a.DetectInjection(ctx, 24); err != nil {
		t.Fatalf("DetectInjection: %v", err)
	}
	if _, err := a.DetectReflectiveLoad(ctx, 24); err != nil {
		t.Fatalf("DetectReflectiveLoad: %v", err)
	}
	if _, err := a.GetArtifacts(ctx, agentID, 24); err != nil {
		t.Fatalf("GetArtifacts: %v", err)
	}
	_ = a.GetStats(ctx)
}
