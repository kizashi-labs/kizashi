package apikeys

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the full API-key lifecycle
// (generate → validate → list → last-used → revoke) against the real schema.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping apikeys coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestManager_Lifecycle_DB(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	// Seed a user (api_keys.user_id references users).
	uid := uuid.NewString()
	if _, err := pool.Exec(ctx, "INSERT INTO users (id, email) VALUES ($1,$2)", uid, "cov-ak-"+uid[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE id=$1", uid) })

	m := NewManager(pool)
	ttl := time.Hour
	key, rawKey, err := m.Generate(ctx, "cov-key", uid, "admin", []string{"read", "write"}, &ttl)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM api_keys WHERE id=$1", key.ID) })

	if _, err := m.Validate(ctx, rawKey); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := m.List(ctx, uid); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := m.ListAll(ctx); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	m.UpdateLastUsed(ctx, key.ID)
	if err := m.Revoke(ctx, key.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}
