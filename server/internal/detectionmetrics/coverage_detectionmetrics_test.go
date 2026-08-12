package detectionmetrics

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. This drives the large Calculate pass
// (MITRE coverage, severity distribution, FP rules, trend) plus the MITRE and
// trend helpers against the empty-but-real schema.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping detectionmetrics coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestTracker_Calculate_DB(t *testing.T) {
	pool := covPool(t)
	tr := NewTracker(pool)
	ctx := context.Background()

	for _, period := range []string{"24h", "7d", "30d"} {
		if _, err := tr.Calculate(ctx, period); err != nil {
			t.Fatalf("Calculate(%s): %v", period, err)
		}
	}
	if _, err := tr.GetMITRECoverage(ctx); err != nil {
		t.Fatalf("GetMITRECoverage: %v", err)
	}
	_ = tr.GetTrend(ctx, "7d")
}
