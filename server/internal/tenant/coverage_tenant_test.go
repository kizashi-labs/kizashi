package tenant

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the full org CRUD lifecycle plus
// GetStats against the real schema.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping tenant coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestStore_CRUD_DB(t *testing.T) {
	pool := covPool(t)
	s := NewStore(pool)
	ctx := context.Background()
	slug := "cov-" + uuid.NewString()[:8]

	org, err := s.Create(ctx, &Organization{
		Name: "Cov Org", Slug: slug, Plan: "pro", AgentLimit: 100, UserLimit: 20, Enabled: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM organizations WHERE id=$1", org.ID) })

	if _, err := s.Get(ctx, org.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.GetBySlug(ctx, slug); err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.GetStats(ctx, org.ID); err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if _, err := s.Update(ctx, org.ID, &Organization{
		Name: "Cov Org 2", Slug: slug, Plan: "enterprise", AgentLimit: 200, UserLimit: 40, Enabled: true,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, org.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
