// Package store provides database access for the EDR server.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/edr-platform/server/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantContextKey is the context key used to propagate tenant_id from the
// HTTP middleware through to pgxpool.PrepareConn, enabling PostgreSQL
// Row-Level Security without modifying individual query handlers.
type TenantContextKey struct{}

// DB wraps a pgx connection pool with helper methods.
type DB struct {
	pool *pgxpool.Pool
}

// Connect establishes a connection pool to PostgreSQL/TimescaleDB.
func Connect(ctx context.Context, databaseURL string) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	config.MaxConns = 30
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	// Attach OTEL query tracer so every SQL statement gets a child span.
	// When no OTEL exporter is configured this is effectively a no-op.
	config.ConnConfig.Tracer = telemetry.NewPgxTracer()

	// PrepareConn: if the request context carries a tenant_id (placed there by
	// tenantMiddleware), set app.tenant_id on the connection so PostgreSQL RLS
	// policies automatically filter rows for the correct tenant. Runs before
	// every acquire (same hook point as the deprecated BeforeAcquire).
	//
	// The 3rd set_config arg MUST be false (session-scoped). With true
	// (transaction-scoped) the setting is discarded at the end of THIS Exec's
	// implicit transaction and is therefore NOT visible to the request's
	// subsequent queries — leaving app.tenant_id empty, which the RLS policies'
	// "app.tenant_id IS NULL OR ''" escape clause treats as full cross-tenant
	// access. AfterRelease clears the session value before the connection is
	// reused, so it cannot bleed to the next tenant.
	config.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		if tid, ok := ctx.Value(TenantContextKey{}).(string); ok && tid != "" {
			_, _ = c.Exec(ctx, "SELECT set_config('app.tenant_id', $1, false)", tid)
		}
		return true, nil
	}

	// AfterRelease: reset app.tenant_id so the connection is clean for the next
	// request (prevents tenant bleed-through in the pool). Must also be session-
	// scoped (false) to actually clear the session value PrepareConn set.
	config.AfterRelease = func(c *pgx.Conn) bool {
		_, _ = c.Exec(context.Background(), "SELECT set_config('app.tenant_id', '', false)")
		return true
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

// Pool returns the underlying pgx pool for direct use in stores.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}
