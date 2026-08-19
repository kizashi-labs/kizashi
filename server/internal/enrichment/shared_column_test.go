package enrichment

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alerts.enrichment is one JSONB column with three writers: this enricher, the
// alert-enrichment pipeline in internal/api/handlers, and the console's enrich
// action. Until they agreed on a shape, this one selected `enrichment IS NULL`
// and then REPLACED the whole object.
//
// Both halves of that were destructive:
//
//   - the selection meant an alert became invisible to this enricher the moment
//     anyone else wrote anything. The enrich button writes {"status":"pending"},
//     so pressing it guaranteed the alert would never be enriched by VirusTotal
//     — the opposite of what it was asked to do.
//   - the write erased whatever the other producers had put in the column.
//
// These tests drive the production predicate and the production write. An
// earlier version restated the SQL in the test instead, which meant mutating
// virustotal.go could not fail it.

// enrichmentPool connects and takes SweepLockKey for the test's duration, so
// internal/api/handlers cannot run its pipeline over these fixtures while the
// assertions are being made. The unlock is registered before any fixture
// cleanup and so, cleanups being LIFO, runs after all of them.
func enrichmentPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire a connection for the sweep lock: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, SweepLockKey); err != nil {
		conn.Release()
		t.Fatalf("take the sweep lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, SweepLockKey)
		conn.Release()
	})
	return pool
}

// seedAlert inserts one alert and returns its id. enrichment is the initial
// contents of the shared column, or "" to leave it NULL.
func seedAlert(t *testing.T, pool *pgxpool.Pool, title, enrichment string) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'vt-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id,title,description,severity,status)
		 VALUES ($1::uuid,$2,'fixture',7,'open') RETURNING id::text`, agentID, title).Scan(&id); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if enrichment != "" {
		if _, err := pool.Exec(ctx,
			`UPDATE alerts SET enrichment = $1::jsonb WHERE id = $2::uuid`, enrichment, id); err != nil {
			t.Fatalf("seed enrichment: %v", err)
		}
	}
	return id
}

// isCandidate applies the enricher's own selection to one alert.
func isCandidate(t *testing.T, pool *pgxpool.Pool, alertID string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM alerts `+vtCandidateWhere+` AND id = $2::uuid`,
		vtSectionKey, alertID).Scan(&n); err != nil {
		t.Fatalf("apply the candidate predicate: %v", err)
	}
	return n == 1
}

// enrichmentOf reads the shared column back as a map.
func enrichmentOf(t *testing.T, pool *pgxpool.Pool, alertID string) map[string]interface{} {
	t.Helper()
	var raw *string
	if err := pool.QueryRow(context.Background(),
		`SELECT enrichment::text FROM alerts WHERE id=$1::uuid`, alertID).Scan(&raw); err != nil {
		t.Fatalf("read enrichment: %v", err)
	}
	if raw == nil {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(*raw), &out); err != nil {
		t.Fatalf("enrichment is not an object: %v (%s)", err, *raw)
	}
	return out
}

// TestAnAlertAnotherProducerHasTouchedIsStillACandidate is the core selection
// gate: the four states another writer can leave the column in must all still
// be visible to this enricher.
func TestAnAlertAnotherProducerHasTouchedIsStillACandidate(t *testing.T) {
	pool := enrichmentPool(t)

	for _, tc := range []struct {
		name       string
		enrichment string
	}{
		{"never touched", ""},
		{"an operator pressed enrich", `{"status":"pending"}`},
		{"the alert-enrichment pipeline ran", `{"status":"done","context":{"tags":["ransomware"]}}`},
		{"an empty object", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := seedAlert(t, pool, "no iocs in this title", tc.enrichment)
			if !isCandidate(t, pool, id) {
				t.Errorf("enrichment=%s makes the alert invisible to the VirusTotal "+
					"enricher, so whichever producer wrote it silently cancelled the "+
					"lookup — permanently, since nothing ever clears the column",
					tc.enrichment)
			}
		})
	}
}

// TestAnAlertVirusTotalHasSeenIsNotACandidate is the other direction: without
// it the poller would re-examine the same alerts every five minutes for ever.
func TestAnAlertVirusTotalHasSeenIsNotACandidate(t *testing.T) {
	pool := enrichmentPool(t)
	id := seedAlert(t, pool, "no iocs in this title",
		`{"status":"done","virustotal":{"checked_at":"2026-01-01T00:00:00Z"}}`)

	if isCandidate(t, pool, id) {
		t.Error("an alert this enricher has already recorded a result for is still " +
			"selected, so every poll re-runs every lookup against a 4 req/min quota")
	}
}

// TestStoringASectionDoesNotDisturbTheOtherProducers drives the production
// write. It used to be `SET enrichment = $1`, which erased the pipeline's
// section and the operator's status flag on every lookup.
func TestStoringASectionDoesNotDisturbTheOtherProducers(t *testing.T) {
	pool := enrichmentPool(t)
	id := seedAlert(t, pool, "no iocs in this title",
		`{"status":"pending","context":{"tags":["ransomware"],"enriched_at":"2026-01-01T00:00:00Z"}}`)

	e := NewVTEnricher(nil, pool, "")
	e.storeSection(context.Background(), id, map[string]interface{}{"found": false})

	after := enrichmentOf(t, pool, id)
	vt, ok := after["virustotal"].(map[string]interface{})
	if !ok || vt["found"] != false {
		t.Fatalf("this enricher's own section was not stored: %v", after)
	}
	if after["status"] != "pending" {
		t.Errorf("status = %v; the operator's pending flag was erased by a "+
			"VirusTotal lookup", after["status"])
	}
	sectionCtx, ok := after["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("the alert-enrichment pipeline's section was erased: %v", after)
	}
	if sectionCtx["enriched_at"] != "2026-01-01T00:00:00Z" {
		t.Errorf("the pipeline's section was rewritten: %v", sectionCtx)
	}
}

// TestAnAlertWithNoIOCsIsRecordedRatherThanRetriedForEver walks the whole path
// for the one case that needs no network: a title carrying neither a hash nor a
// public IP. The alert has to stop being a candidate afterwards, or the poller
// picks it up again every five minutes until it ages out of the 24h window.
func TestAnAlertWithNoIOCsIsRecordedRatherThanRetriedForEver(t *testing.T) {
	pool := enrichmentPool(t)
	id := seedAlert(t, pool, "権限昇格の疑い (192.168.1.10)", `{"status":"pending"}`)

	if !isCandidate(t, pool, id) {
		t.Fatal("the fixture is not a candidate, so this test measures nothing")
	}
	NewVTEnricher(nil, pool, "").enrichAlert(context.Background(), id)

	if isCandidate(t, pool, id) {
		t.Error("the alert is still a candidate after being examined; nothing was " +
			"recorded, so the poller will re-examine it on every tick")
	}
	after := enrichmentOf(t, pool, id)
	vt, ok := after["virustotal"].(map[string]interface{})
	if !ok || vt["checked_at"] == nil {
		t.Errorf("no result was recorded for an alert with no IOCs: %v", after)
	}
	if after["status"] != "pending" {
		t.Errorf("status = %v; examining the alert erased the operator's flag", after["status"])
	}
}
