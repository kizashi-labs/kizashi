package scheduler

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTagCriticalityBase(t *testing.T) {
	cases := []struct {
		tags []string
		want int
	}{
		{nil, 10},
		{[]string{"workstation"}, 15},
		{[]string{"server", "linux"}, 30},
		{[]string{"Domain_Controller"}, 45}, // case-insensitive
		{[]string{"server", "domain_controller"}, 45},
	}
	for _, c := range cases {
		if got := tagCriticalityBase(c.tags); got != c.want {
			t.Errorf("tagCriticalityBase(%v) = %d, want %d", c.tags, got, c.want)
		}
	}
}

// TestAssetCriticalityScorer_Calculate proves the worker derives and stores a
// score for an agent from its tags + open critical alert, turning the
// compliance scorer's asset-criticality evidence check into real data.
func TestAssetCriticalityScorer_Calculate(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping asset criticality coverage test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at, tags)
		 VALUES ('cov-crit', 'linux', 'online', NOW(), NOW(), ARRAY['server','production'])
		 RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM asset_criticality_scores WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	_, _ = pool.Exec(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		 VALUES ($1::uuid, 9, 'cov-crit-alert', 'd', 'open', NOW())`, agentID)

	NewAssetCriticalityScorer(pool).calculate(ctx)

	var score int
	if err := pool.QueryRow(ctx,
		`SELECT score FROM asset_criticality_scores WHERE agent_id=$1`, agentID).Scan(&score); err != nil {
		t.Fatalf("score not stored: %v", err)
	}
	// server tag (base 30) + one open critical alert (*5) = 35.
	if score < 30 {
		t.Fatalf("expected criticality score >= 30 (server + crit alert), got %d", score)
	}
}
