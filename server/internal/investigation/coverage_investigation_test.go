package investigation

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInvestigator_DBReads(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	inv := NewInvestigator(pool, InvestigatorConfig{})
	_ = inv.IsConfigured()
	if inv.DB() == nil {
		t.Fatal("DB() nil")
	}
	_ = inv.ReadModeFromDB(context.Background())
}
