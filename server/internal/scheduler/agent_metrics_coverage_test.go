package scheduler

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCheckCPUMemory_FlagsHighUsage proves the fleet health alerter fix: an
// online agent whose persisted heartbeat metrics exceed the CPU/memory
// thresholds is now flagged (previously the query read a non-existent
// agents.settings column and never fired).
func TestCheckCPUMemory_FlagsHighUsage(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping agent metrics coverage test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	// Online agent with 95% CPU and 7500/8000 MB (~94%) memory, metrics fresh.
	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at,
		     total_memory_mb, cpu_usage, memory_usage_mb, metrics_updated_at)
		 VALUES ('cov-metrics', 'linux', 'online', NOW(), NOW(),
		     8000, 95, 7500, NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

	issues := NewAgentHealthAlerter(pool, nil).checkCPUMemory(ctx)
	found := false
	for _, is := range issues {
		if is.agentID == agentID {
			found = true
		}
	}
	if !found {
		t.Fatalf("high-CPU/memory agent %s not flagged by checkCPUMemory", agentID)
	}
}
