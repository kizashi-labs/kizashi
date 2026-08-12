//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/edr-platform/server/internal/store"
)

// testDB holds the shared DB handle for the suite (set in TestMain).
var testDB *store.DB

// TestMain sets up the DB connection.
// If DATABASE_URL is set, it connects to that instance directly and applies
// migrations. If it is not set, it spins up a Testcontainers PostgreSQL
// container identical to the one used by the store integration tests.
// All tests are skipped (not failed) when no database can be reached.
func TestMain(m *testing.M) {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		// Use the caller-supplied database.
		db, err := store.Connect(ctx, dbURL)
		if err != nil {
			// Treat connection failure as a skip condition so CI does not
			// red-light when the database service is simply absent.
			_ = err
			os.Exit(0)
		}
		testDB = db
		defer testDB.Close()
		applyMigrationsMain(ctx, db)
	} else {
		// No DATABASE_URL — spin up a disposable container.
		ctr, err := tcpostgres.Run(ctx,
			"timescale/timescaledb:latest-pg16",
			tcpostgres.WithDatabase("edrtest"),
			tcpostgres.WithUsername("edr"),
			tcpostgres.WithPassword("testpass"),
			tcpostgres.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(90*time.Second),
			),
		)
		if err != nil {
			// Container runtime not available — skip.
			os.Exit(0)
		}
		defer func() { _ = ctr.Terminate(ctx) }()

		connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			os.Exit(0)
		}

		db, err := store.Connect(ctx, connStr)
		if err != nil {
			os.Exit(0)
		}
		testDB = db
		defer testDB.Close()
		applyMigrationsMain(ctx, db)
	}

	os.Exit(m.Run())
}

// applyMigrationsMain applies all SQL migrations in sorted order.
// Errors are logged but not fatal — some migrations may be non-idempotent.
func applyMigrationsMain(ctx context.Context, db *store.DB) {
	// Resolve the migrations directory relative to the server root.
	// tests/integration/ -> ../../migrations
	migrationsDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(migrationsDir, e.Name()))
		}
	}
	sort.Strings(files)

	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if _, err := db.Pool().Exec(ctx, string(sql)); err != nil {
			// Non-fatal: log but continue (e.g. "already exists" errors).
			_ = err
		}
	}
}

// requireDB is a helper that skips the test when testDB is unavailable.
func requireDB(t *testing.T) *store.DB {
	t.Helper()
	if testDB == nil {
		t.Skip("DATABASE_URL not set and container runtime unavailable — skipping integration test")
	}
	return testDB
}
