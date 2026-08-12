package reports

import (
	"context"
	"os"
	"testing"
	"time"

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

func TestGenerator_AllTypes(t *testing.T) {
	g := NewGenerator(covPool(t))
	ctx := context.Background()
	dr := DateRange{Start: time.Now().Add(-7 * 24 * time.Hour), End: time.Now()}
	for _, typ := range []string{"executive_summary", "compliance_report", "incident_report", "threat_summary"} {
		spec := &ReportSpec{ID: "cov", Type: typ, Title: "cov", DateRange: dr, Format: "json"}
		res, err := g.Generate(ctx, spec)
		if err != nil {
			t.Fatalf("Generate(%s): %v", typ, err)
		}
		if res != nil {
			if _, err := g.ToCSV(res.Data); err != nil {
				t.Logf("ToCSV(%s): %v", typ, err)
			}
		}
	}
}
