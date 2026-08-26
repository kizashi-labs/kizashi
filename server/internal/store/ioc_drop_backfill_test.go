package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 379 drops ioc_type, enabled and threat_level, and threat_level is
// the only one holding anything unique: the enrichment cache wrote
// live.Score/10 there while leaving severity at its default of 7. Dropping it
// without carrying those across would silently reset every externally-enriched
// indicator to the default.
//
// This runs the migration's own SQL against a table in the shape it had
// beforehand, rather than re-implementing the backfill and testing the copy.

// TestMigration379CarriesThreatLevelAcross applies the migration to a database
// of its own.
//
// It has to be a database rather than a schema: the migration's guard reads
// information_schema WHERE table_schema = 'public', which is right in
// production and means a copy parked in another schema is invisible to it. A
// scratch database gives the copy a public schema of its own.
func TestMigration379CarriesThreatLevelAcross(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	ctx := context.Background()

	sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations",
		"440_ioc_entries_drop_compat_columns.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	migration := string(sqlBytes)
	if !strings.Contains(migration, "threat_level") {
		t.Fatal("migration 379 no longer mentions threat_level — this test is checking nothing")
	}

	const scratch = "mig379_scratch"
	admin, err := pgxpool.New(ctx, swapDatabase(dsn, "postgres"))
	if err != nil {
		t.Skipf("cannot reach the maintenance database: %v", err)
	}
	// Registered first so it runs LAST: cleanups are LIFO, and the drop below
	// needs this pool still open. A `defer` here would close it before any
	// t.Cleanup ran.
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+scratch); err != nil {
		t.Skipf("cannot create a scratch database here: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+scratch); err != nil {
		t.Skipf("cannot create a scratch database here: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+scratch)
	})

	pool, err := pgxpool.New(ctx, swapDatabase(dsn, scratch))
	if err != nil {
		t.Fatalf("connect to scratch: %v", err)
	}
	// Registered after the DROP DATABASE cleanup, so it runs before it —
	// Postgres refuses to drop a database that still has connections.
	t.Cleanup(pool.Close)

	// ioc_entries as it stood before 379: both halves of each pair present.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE ioc_entries (
			id           SERIAL PRIMARY KEY,
			type         TEXT NOT NULL,
			value        TEXT NOT NULL,
			severity     INT  NOT NULL DEFAULT 7 CHECK (severity >= 1 AND severity <= 10),
			is_active    BOOLEAN DEFAULT TRUE,
			ioc_type     TEXT,
			enabled      BOOLEAN NOT NULL DEFAULT TRUE,
			threat_level INT NOT NULL DEFAULT 5
		)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, severity, threat_level) VALUES
			('domain','enriched.example',  7, 9),
			('domain','imported.example',  3, 5),
			('domain','lowscore.example',  7, 0),
			('domain','topscore.example',  7, 40)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := pool.Exec(ctx, migration); err != nil {
		t.Fatalf("migration 379 failed: %v", err)
	}

	want := map[string]int{
		"enriched.example": 9,  // the cache's threat level carried across
		"imported.example": 3,  // threat_level was its default, so severity kept
		"lowscore.example": 1,  // clamped up to the CHECK minimum
		"topscore.example": 10, // clamped down to the maximum
	}
	for value, expected := range want {
		var got int
		if err := pool.QueryRow(ctx,
			`SELECT severity FROM ioc_entries WHERE value=$1`, value).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", value, err)
		}
		if got != expected {
			t.Errorf("%s の severity が %d、期待は %d", value, got, expected)
		}
	}

	for _, gone := range []string{"ioc_type", "enabled", "threat_level"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			 WHERE table_schema='public' AND table_name='ioc_entries' AND column_name=$1)`,
			gone).Scan(&exists); err != nil {
			t.Fatalf("column check: %v", err)
		}
		if exists {
			t.Errorf("%s が削除されていません", gone)
		}
	}
}

// swapDatabase points a DSN at another database on the same server.
func swapDatabase(dsn, db string) string {
	if i := strings.Index(dsn, "?"); i >= 0 {
		base, query := dsn[:i], dsn[i:]
		if j := strings.LastIndex(base, "/"); j >= 0 {
			return base[:j+1] + db + query
		}
		return dsn
	}
	if j := strings.LastIndex(dsn, "/"); j >= 0 {
		return dsn[:j+1] + db
	}
	return dsn
}
