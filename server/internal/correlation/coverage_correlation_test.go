package correlation

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the DB-backed incident reader
// (GetIncidents → fetchIncidentsFromDB) plus the in-memory rule/stat accessors.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping correlation coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestEngine_IncidentsAndStats_DB(t *testing.T) {
	pool := covPool(t)
	e := NewEngine(pool)
	ctx := context.Background()

	// Seed a correlation incident (with the correlation-only columns added by
	// migration 323) and read it back — proving fetchIncidentsFromDB works.
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (id, title, description, severity, status,
		     alert_ids, agent_ids, mitre_tactic, mitre_tech, correlation_rule_id)
		 VALUES (gen_random_uuid(), 'cov-corr-inc', 'd', 7, 'open',
		     '{}', '{}', 'TA0001', 'T1059', 'cov-rule')`); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM incidents WHERE title='cov-corr-inc'") })

	incs, err := e.GetIncidents(ctx, 50)
	if err != nil {
		t.Fatalf("GetIncidents: %v", err)
	}
	found := false
	for _, inc := range incs {
		if inc.Title == "cov-corr-inc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded correlation incident not returned by GetIncidents")
	}
	_ = e.GetStats()
	_ = e.ListRules()
	if _, ok := e.GetIncidentByID("does-not-exist"); ok {
		t.Fatalf("GetIncidentByID should miss for unknown id")
	}
	// In-memory status update on an absent id is a no-op; exercises the guard.
	e.UpdateIncidentStatus("does-not-exist", "resolved")
}
