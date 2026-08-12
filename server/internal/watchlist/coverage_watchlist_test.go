package watchlist

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the DB-backed list/stats read
// paths against the empty-but-real watchlist table.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping watchlist coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestStore_ListStats_DB(t *testing.T) {
	pool := covPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	for _, et := range []string{"", "ip", "domain", "hash"} {
		if _, _, err := s.List(ctx, et); err != nil {
			t.Fatalf("List(%q): %v", et, err)
		}
	}
	_ = s.GetStats(ctx)
}
