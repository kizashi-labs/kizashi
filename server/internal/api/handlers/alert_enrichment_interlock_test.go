package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/edr-platform/server/internal/enrichment"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alerts.enrichment is one JSONB column with three writers that did not agree
// on what it holds:
//
//	internal/enrichment (VirusTotal)   selected `enrichment IS NULL` and
//	                                   REPLACED the whole object
//	AlertActionHandler.Enrich          jsonb_set(..., '{status}', '"pending"')
//	AlertEnrichmentPipeline            enrichment_status / enrichment_data,
//	                                   which no migration creates
//
// Measured against the migrated schema before this change:
//
//	alerts.enrichment          exists=true
//	alerts.enrichment_status   exists=false
//	alerts.enrichment_data     exists=false
//	POST /alerts/:id/enrich -> 202 {"status":"pending", ...}
//	alerts.enrichment after the action:        {"status": "pending"}
//	alerts.enrichment after the pipeline ran:  {"status": "pending"}
//
// The pipeline returned at a column-existence check on every tick since it was
// written, so no alert has ever been enriched by it. And the console's enrich
// button made things worse rather than doing nothing: writing
// {"status":"pending"} makes enrichment non-NULL, which permanently excluded
// the alert from the VirusTotal enricher's `enrichment IS NULL` — pressing
// enrich guaranteed the alert would never be enriched at all.

// enrichPool connects and takes enrichment.SweepLockKey for the test's
// duration. enrich() selects the 20 newest candidates across the whole alerts
// table, so running it here rewrites fixtures belonging to any package
// executing concurrently — internal/enrichment seeds rows that look exactly
// like candidates. The unlock is registered before any fixture cleanup and so,
// cleanups being LIFO, runs after all of them.
func enrichPool(t *testing.T) *pgxpool.Pool {
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
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, enrichment.SweepLockKey); err != nil {
		conn.Release()
		t.Fatalf("take the sweep lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, enrichment.SweepLockKey)
		conn.Release()
	})
	return pool
}

// seedAlert creates one alert with a title the pipeline can find IOCs in.
func seedAlert(t *testing.T, pool *pgxpool.Pool, title string) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'enrich-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id,title,description,severity,status)
		 VALUES ($1::uuid,$2,'fixture',7,'open') RETURNING id::text`, agentID, title).Scan(&id); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	return id
}

// enrichmentOf reads the column back as a map.
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

// pressEnrich invokes the console's enrich action.
func pressEnrich(t *testing.T, pool *pgxpool.Pool, alertID string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/alerts/"+alertID+"/enrich", nil)
	c.Params = gin.Params{{Key: "id", Value: alertID}}
	NewAlertActionHandler(pool).Enrich(c)
	return w.Code
}

// TestPressingEnrichEventuallyEnrichesTheAlert is the core gate: the action and
// the pipeline have to be two halves of one mechanism.
func TestPressingEnrichEventuallyEnrichesTheAlert(t *testing.T) {
	pool := enrichPool(t)
	alertID := seedAlert(t, pool, "不審な外部通信 ransomware 203.0.113.9")

	if code := pressEnrich(t, pool, alertID); code != http.StatusAccepted {
		t.Fatalf("enrich action: status = %d", code)
	}
	if got := enrichmentOf(t, pool, alertID)["status"]; got != "pending" {
		t.Fatalf("status after the action = %v, want pending", got)
	}

	NewAlertEnrichmentPipeline(pool).enrich(context.Background())

	after := enrichmentOf(t, pool, alertID)
	if after["status"] != enrichmentStatusDone {
		t.Errorf("status = %v after the pipeline ran, want %q. The pipeline reads "+
			"columns no migration creates and returns at a column-existence check, "+
			"so an alert an operator asked to enrich stays pending for ever.",
			after["status"], enrichmentStatusDone)
	}
	section, ok := after[enrichmentContextKey].(map[string]interface{})
	if !ok {
		t.Fatalf("no %q section was written: %v", enrichmentContextKey, after)
	}
	if section["enriched_at"] == nil {
		t.Error("the enrichment carries no timestamp")
	}
	tags, _ := section["tags"].([]interface{})
	found := false
	for _, tag := range tags {
		if tag == "ransomware" {
			found = true
		}
	}
	if !found {
		t.Errorf("tags = %v; the pipeline's own keyword matching produced nothing "+
			"for a title containing \"ransomware\"", tags)
	}
}

// TestAnAlertNobodyAskedAboutIsStillEnriched. The pipeline also sweeps alerts
// with no enrichment at all; that arm must not have been lost.
func TestAnAlertNobodyAskedAboutIsStillEnriched(t *testing.T) {
	pool := enrichPool(t)
	alertID := seedAlert(t, pool, "mimikatz の実行を検出")

	if e := enrichmentOf(t, pool, alertID); e != nil {
		t.Fatalf("the fixture already has enrichment: %v", e)
	}
	NewAlertEnrichmentPipeline(pool).enrich(context.Background())

	if got := enrichmentOf(t, pool, alertID)["status"]; got != enrichmentStatusDone {
		t.Errorf("status = %v, want %q", got, enrichmentStatusDone)
	}
}

// TestTheEnrichmentPipelineDoesNotRedoFinishedWork. It runs every 30 seconds;
// re-enriching everything on every tick would hammer the geo-IP lookup and
// rewrite the timestamp for ever.
func TestTheEnrichmentPipelineDoesNotRedoFinishedWork(t *testing.T) {
	pool := enrichPool(t)
	alertID := seedAlert(t, pool, "beacon らしき通信")

	p := NewAlertEnrichmentPipeline(pool)
	p.enrich(context.Background())
	first := enrichmentOf(t, pool, alertID)
	firstSection, _ := first[enrichmentContextKey].(map[string]interface{})
	if firstSection == nil {
		t.Fatal("nothing was enriched on the first pass")
	}
	p.enrich(context.Background())

	second := enrichmentOf(t, pool, alertID)
	secondSection, _ := second[enrichmentContextKey].(map[string]interface{})
	if secondSection == nil {
		t.Fatal("the enrichment disappeared on the second pass")
	}
	if firstSection["enriched_at"] != secondSection["enriched_at"] {
		t.Errorf("the alert was enriched again on the second pass (%v -> %v)",
			firstSection["enriched_at"], secondSection["enriched_at"])
	}
}

// TestThePipelineDoesNotEraseAnotherEnrichersSection. The column is shared, and
// the VirusTotal enricher used to replace it wholesale. Merging is what lets
// the two coexist.
//
// The fixture has to be an alert the pipeline actually selects, which is the
// realistic sequence anyway: VirusTotal enriches an alert, an operator then
// presses enrich, and the pipeline picks it up on the next tick. An earlier
// version of this test seeded only the VirusTotal section — that alert is
// neither NULL nor pending, so the pipeline skipped it and the test passed
// however the write was mutated.
func TestThePipelineDoesNotEraseAnotherEnrichersSection(t *testing.T) {
	pool := enrichPool(t)
	alertID := seedAlert(t, pool, "cobalt strike の疑い")

	if _, err := pool.Exec(context.Background(),
		`UPDATE alerts SET enrichment = '{"virustotal":{"hash":"abc123"}}'::jsonb WHERE id=$1::uuid`,
		alertID); err != nil {
		t.Fatalf("seed another enricher's section: %v", err)
	}
	if code := pressEnrich(t, pool, alertID); code != http.StatusAccepted {
		t.Fatalf("enrich action: status = %d", code)
	}
	if before := enrichmentOf(t, pool, alertID); before["virustotal"] == nil {
		t.Fatalf("the enrich action itself erased the VirusTotal section: %v", before)
	}

	NewAlertEnrichmentPipeline(pool).enrich(context.Background())

	after := enrichmentOf(t, pool, alertID)
	if after["status"] != enrichmentStatusDone {
		t.Fatalf("the pipeline did not process the alert (status=%v), so this test "+
			"is not measuring the write at all", after["status"])
	}
	vt, ok := after["virustotal"].(map[string]interface{})
	if !ok || vt["hash"] != "abc123" {
		t.Errorf("the VirusTotal section was lost: %v", after)
	}
}

// TestTheEnrichActionOnlyAddsItsOwnKey. The action writes into a column two
// background enrichers also write to; anything beyond a top-level status is
// somebody else's data.
//
// The other half of the interlock — that {"status":"pending"} does not exclude
// an alert from the VirusTotal enricher, which is what `enrichment IS NULL`
// used to do — is pinned in internal/enrichment against the production query.
func TestTheEnrichActionOnlyAddsItsOwnKey(t *testing.T) {
	pool := enrichPool(t)
	alertID := seedAlert(t, pool, "外部通信 203.0.113.9")

	if _, err := pool.Exec(context.Background(),
		`UPDATE alerts SET enrichment = '{"virustotal":{"hash":"abc123"}}'::jsonb WHERE id=$1::uuid`,
		alertID); err != nil {
		t.Fatalf("seed another enricher's section: %v", err)
	}
	if code := pressEnrich(t, pool, alertID); code != http.StatusAccepted {
		t.Fatalf("enrich action: status = %d", code)
	}

	after := enrichmentOf(t, pool, alertID)
	if after["status"] != enrichmentStatusPending {
		t.Errorf("status = %v after the action, want %q", after["status"], enrichmentStatusPending)
	}
	vt, ok := after["virustotal"].(map[string]interface{})
	if !ok || vt["hash"] != "abc123" {
		t.Errorf("pressing enrich destroyed the VirusTotal enricher's section: %v", after)
	}
}
