package compliance

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestControlCatalogs(t *testing.T) {
	if len(CISControls()) == 0 {
		t.Fatal("CISControls empty")
	}
	if len(NISTControls()) == 0 {
		t.Fatal("NISTControls empty")
	}
}

func TestEvaluator_DBPaths(t *testing.T) {
	pool := covPool(t)
	e := NewEvaluator(pool)
	ctx := context.Background()
	for _, fw := range []Framework{FrameworkCIS, FrameworkNIST, FrameworkSOC2} {
		if _, err := e.EvaluateAll(ctx, fw); err != nil {
			t.Fatalf("EvaluateAll(%s): %v", fw, err)
		}
	}
	if _, err := e.GetOrgSummary(ctx); err != nil {
		t.Fatalf("GetOrgSummary: %v", err)
	}
}

func TestChecker_DBPaths(t *testing.T) {
	pool := covPool(t)
	c := NewChecker(pool)
	ctx := context.Background()
	if _, err := c.GetFleetCompliance(ctx); err != nil {
		t.Fatalf("GetFleetCompliance: %v", err)
	}
	_ = c.GetComplianceStats(ctx)
}
