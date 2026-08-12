package audit

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. These drive the DB-backed audit query /
// stats / export paths, including the conditional WHERE-clause builder (every
// filter field set), against the empty-but-real audit_events table.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping audit coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestLogger_QueryStatsExport_DB(t *testing.T) {
	pool := covPool(t)
	l := NewLogger(pool)
	ctx := context.Background()

	// Every filter field set so the dynamic WHERE builder walks all branches.
	filter := AuditFilter{
		UserID:    "cov-user",
		Action:    "login",
		Resource:  "session",
		StartTime: "2020-01-01T00:00:00Z",
		EndTime:   "2030-01-01T00:00:00Z",
		OrgID:     "cov-org",
		Limit:     25,
		Offset:    0,
	}
	if _, _, err := l.Query(ctx, filter); err != nil {
		t.Fatalf("Query: %v", err)
	}

	// Empty filter exercises the default limit + minimal WHERE.
	if _, _, err := l.Query(ctx, AuditFilter{}); err != nil {
		t.Fatalf("Query empty: %v", err)
	}

	if _, err := l.ExportCSV(ctx, filter); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	if _, err := l.GetStats(ctx, "cov-org"); err != nil {
		t.Fatalf("GetStats: %v", err)
	}
}
