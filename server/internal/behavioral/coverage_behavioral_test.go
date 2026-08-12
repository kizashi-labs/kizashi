package behavioral

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema) and returns a
// pool, skipping when the var is unset so pure-logic runs stay green. These
// tests drive the DB-backed baseline builders against empty-but-real tables:
// the queries find nothing, so the builder helpers traverse their empty-result
// paths — exercising the query/guard code that pure tests cannot reach.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping behavioral coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestEngine_BaselineBuilders_DB(t *testing.T) {
	pool := covPool(t)
	e := NewEngine(pool)
	ctx := context.Background()
	agentID := "00000000-0000-0000-0000-0000000000ab"

	// BuildBaseline over an empty event history returns a baseline (or a
	// not-enough-data path) without error and populates the in-memory map.
	if _, err := e.BuildBaseline(ctx, agentID, 14); err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}

	// BuildEnrichedBaseline drives buildHeatmap / buildTypicalProcesses /
	// buildTypicalDests / buildTypicalDirs / buildRecentDeviations against the
	// empty tables.
	if _, err := e.BuildEnrichedBaseline(ctx, agentID, 30, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("BuildEnrichedBaseline: %v", err)
	}
	// lookbackDays<=0 exercises the default branch.
	if _, err := e.BuildEnrichedBaseline(ctx, agentID, 0, nil); err != nil {
		t.Fatalf("BuildEnrichedBaseline default: %v", err)
	}

	// In-memory accessors.
	_, _ = e.GetBaseline(agentID)
	_ = e.GetAllBaselines()
	_ = e.GetRecentAnomalies(10)
}
