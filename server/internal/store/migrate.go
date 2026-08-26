// Package store provides database connection and migration utilities.
package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations applies all pending SQL migrations from migrationsDir.
// Applied migrations are tracked in the schema_migrations table.
// Only migrations not yet recorded are executed, making this safe to call
// on every startup.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) error {
	// Ensure tracking table exists
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT        PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Load already-applied versions
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}
	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scan migration version: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate applied migrations: %w", err)
	}

	// Collect migration files in sorted order
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations directory %q: %w", migrationsDir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Apply pending migrations inside individual transactions
	appliedCount := 0
	for _, name := range files {
		if applied[name] {
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			return fmt.Errorf("read migration file %q: %w", name, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin transaction for %q: %w", name, err)
		}

		if _, err := tx.Exec(ctx, string(content)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %q: %w", name, err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %q: %w", name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %q: %w", name, err)
		}

		slog.Info("マイグレーション適用完了", "file", name)
		appliedCount++
	}

	if appliedCount == 0 {
		slog.Info("マイグレーション: 変更なし（全て適用済み）")
	} else {
		slog.Info("マイグレーション完了", "applied", appliedCount, "total", len(files))
	}
	return nil
}

// MigrationState reports how many migrations the database has applied and which
// one is newest. Both come from schema_migrations, so they describe the DATABASE
// rather than the binary — which is exactly what is needed to answer "is this
// deployment running the code I think it is?".
//
// A build identifier alone cannot answer that. On 2026-08-03 a deployment served
// traffic for days with an image whose migration set stopped 20+ files short of the
// repository, and nothing surfaced it: the API looked healthy, the version string
// looked plausible, and the missing migrations were rule definitions whose absence
// only shows up as detections that never fire. The applied count and newest file
// are cheap, unambiguous, and impossible to fake by rebuilding with a stale context.
func MigrationState(ctx context.Context, pool *pgxpool.Pool) (count int, latest string, err error) {
	err = pool.QueryRow(ctx, `
		SELECT count(*), coalesce(max(version), '')
		FROM schema_migrations`).Scan(&count, &latest)
	if err != nil {
		return 0, "", fmt.Errorf("query migration state: %w", err)
	}
	return count, latest, nil
}
