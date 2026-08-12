package timeline

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. These drive the DB-backed timeline
// builders (agent/incident/alert) whose large query + event-assembly loops the
// pure helper tests cannot reach.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping timeline coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestBuilder_Timelines_DB(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	// Seed an agent, a process event, and an alert so the builders traverse
	// their event-assembly loops rather than returning early on empty results.
	var agentID, alertID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-tl', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

	_, _ = pool.Exec(ctx,
		`INSERT INTO events (agent_id, event_type, raw_data, time)
		 VALUES ($1::uuid, 'process',
		   '{"pid":"200","process_name":"curl","command_line":"curl http://x","hostname":"cov-tl"}'::jsonb, NOW())`,
		agentID)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM events WHERE agent_id=$1", agentID) })

	_ = pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		 VALUES ($1::uuid, 8, 'cov-tl-alert', 'd', 'open', NOW()) RETURNING id::text`, agentID).Scan(&alertID)
	if alertID != "" {
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
	}

	b := NewBuilder(pool)

	if _, err := b.BuildAgentTimeline(ctx, agentID, 24); err != nil {
		t.Fatalf("BuildAgentTimeline: %v", err)
	}
	if alertID != "" {
		if _, err := b.BuildAlertTimeline(ctx, alertID); err != nil {
			t.Fatalf("BuildAlertTimeline: %v", err)
		}
	}
	// Incident timeline against a random (absent) id still runs the query/guard
	// path; tolerate a not-found error.
	_, _ = b.BuildIncidentTimeline(ctx, "00000000-0000-0000-0000-0000000000cd")
}
