package siem

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the connector's DB load and the
// alert/batch dispatch guard paths against an empty (no configured targets) DB.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping siem coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestConnector_LoadAndDispatch_DB(t *testing.T) {
	pool := covPool(t)
	c := NewConnector(pool)
	ctx := context.Background()

	if err := c.LoadFromDB(ctx); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
	// No connectors configured → dispatch is a no-op, exercising the guard paths
	// without any outbound network.
	if err := c.SendAlert(ctx, map[string]interface{}{"title": "cov", "severity": 9}); err != nil {
		t.Fatalf("SendAlert: %v", err)
	}
	if err := c.SendBatch(ctx, []map[string]interface{}{{"title": "cov"}}); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
}
