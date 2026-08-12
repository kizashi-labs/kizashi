package scorecard

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. The scorer drives many per-control
// scoring passes; against empty-but-real tables they traverse their COUNT/query
// guard paths and return default (low) scores — exercising the large scoreX
// functions that pure tests cannot reach.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping scorecard coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestScorer_Frameworks_DB(t *testing.T) {
	pool := covPool(t)
	s := NewScorer(pool)
	ctx := context.Background()

	nist, err := s.CalculateNISTCSF(ctx)
	if err != nil {
		t.Fatalf("CalculateNISTCSF: %v", err)
	}
	if nist == nil {
		t.Fatalf("CalculateNISTCSF returned nil scorecard")
	}

	iso, err := s.CalculateISO27001(ctx)
	if err != nil {
		t.Fatalf("CalculateISO27001: %v", err)
	}
	if iso == nil {
		t.Fatalf("CalculateISO27001 returned nil scorecard")
	}
}

// TestScorer_SoftwareInventoryControl proves the #2 fix: the software-asset
// inventory control (ID.AM-2) now counts rows from endpoint_software (the table
// the agent's software reporter populates) rather than the non-existent
// software_inventory, so it reflects real inventory.
func TestScorer_SoftwareInventoryControl(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-sw', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM endpoint_software WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO endpoint_software (agent_id, name, version) VALUES ($1::uuid, 'openssl', '3.0.2')`, agentID); err != nil {
		t.Fatalf("seed software: %v", err)
	}

	sc, err := NewScorer(pool).CalculateNISTCSF(ctx)
	if err != nil {
		t.Fatalf("CalculateNISTCSF: %v", err)
	}
	var amel *Control
	for _, c := range sc.Controls {
		if c.ID == "ID.AM-2" {
			amel = c
		}
	}
	if amel == nil {
		t.Fatalf("ID.AM-2 control missing")
	}
	if amel.Score <= 0 {
		t.Fatalf("software inventory control did not score with seeded endpoint_software: %+v", amel)
	}
}
