package scheduler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/edr-platform/server/internal/store"
)

// covSchedDB connects to TEST_DATABASE_URL (the migrated DB-backed test schema)
// and returns a *store.DB, skipping when the var is unset so pure-logic runs
// stay green. These tests drive scheduler worker passes against empty-but-real
// tables: the workers query, find nothing to do, and return — exercising the
// query/guard paths that pure-logic tests cannot reach.
func covSchedDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping scheduler coverage tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// covNATS returns a connection to the local NATS, or nil if unavailable (the
// worker publish paths tolerate a nil/absent broker on empty result sets).
func covNATS(t *testing.T) *nats.Conn {
	t.Helper()
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url)
	if err != nil {
		return nil
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestScheduler_Workers(t *testing.T) {
	db := covSchedDB(t)
	pool := db.Pool()
	nc := covNATS(t)
	// Bound the whole worker sweep so a single slow worker can never approach
	// the package's `go test -timeout` budget (the suite runs under -race in CI).
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Seed a minimal fixture (agent + alert + IOC) so the workers traverse their
	// per-row processing loops rather than returning early on empty tables.
	//
	// Every cleanup below uses context.Background() rather than ctx. t.Cleanup
	// functions run AFTER the test function returns, and the test function's own
	// `defer cancel()` runs first — so a DELETE issued on ctx is executed against
	// an already-cancelled context and does nothing. It fails silently, because
	// the error is discarded, which is exactly what a cleanup's error usually
	// should be.
	//
	// Measured: 36 leftover 'cov-sched' agents and 36 'cov-sched2' had
	// accumulated in the shared test database, one pair per run. They eventually
	// broke an unrelated test — TestBugfix_RiskScores_CountsAlertSeverity reads a
	// LIMITed risk-score list, and the leaked agents crowded its own fixture off
	// the first page. A leaking fixture does not stay a local problem on a shared
	// database.
	var agentID, alertID string
	_ = pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-sched', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID)
	if agentID != "" {
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM agents WHERE id=$1", agentID) })
		_ = pool.QueryRow(ctx,
			`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
			 VALUES ($1, 8, 'cov-sched-alert', 'd', 'open', NOW()) RETURNING id::text`, agentID).Scan(&alertID)
		if alertID != "" {
			t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM alerts WHERE id=$1", alertID) })
		}
		// Seed a burst of recent connections to one high-risk destination so the
		// NetworkAnomalyDetector traverses its per-row loops (new-port + beaconing
		// paths) rather than returning on an empty result set.
		_, _ = pool.Exec(ctx,
			`INSERT INTO network_connections (time, agent_id, src_ip, src_port, dst_ip, dst_port, protocol, direction)
			 SELECT NOW(), $1::uuid, '10.0.0.5', 5000, '203.0.113.9', 4444, 'tcp', 'outbound'
			 FROM generate_series(1, 60)`, agentID)
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DELETE FROM network_connections WHERE agent_id=$1", agentID)
		})
	}
	_, _ = pool.Exec(ctx,
		`INSERT INTO ioc_entries (type, value, description, severity, is_active)
		 VALUES ('ip', '198.51.100.7', 'cov', 5, true) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM ioc_entries WHERE value='198.51.100.7'") })

	// pool-only workers
	NewComplianceScorer(pool).calculate(ctx)
	NewDataRetentionCleaner(pool, 90, 90, 90).runOnce(ctx)
	NewIOCExpirySweeper(pool, 0).sweep(ctx)
	NewIncidentEscalator(pool).escalate(ctx)
	NewSecurityKPICollector(pool, 0).seedDefaults(ctx)
	NewSecurityKPICollector(pool, 0).runOnce(ctx)
	NewSecurityMetricsCollector(pool, 0).runOnce(ctx)

	// pool + nats workers
	NewAgentHealthAlerter(pool, nc).checkHealth(ctx)
	NewAlertDigestSender(pool, nc).sendDailyDigest(ctx)
	NewAPIKeyRotator(pool, nc).rotate(ctx)
	NewCertExpiryChecker(pool, nc).checkCerts(ctx)
	NewHuntScheduler(pool, nc).runScheduledHunts(ctx)
	NewMDMCredentialExpiryChecker(pool, nc).check(ctx)
	NewVulnerabilityScanner(pool, nc).scan(ctx)

	// workers needing store/deps
	NewAgentCertRenewer(store.NewAgentStore(db), nc).checkAndRenew(ctx)
	// NOTE: FeedScheduler.processFeeds fetches remote threat feeds over the
	// network — excluded here to keep the suite hermetic and fast (it made the
	// -race run occasionally exceed the per-package timeout).

	// second wave of pool / pool+nats workers
	NewBillingGraceNotifier(pool).check(ctx)
	NewDeadAgentCleanup(pool, nc).cleanup(ctx)
	NewDigestScheduler(pool, []string{"cov@example.com"}).sendDailyDigest(ctx)
	NewHeartbeatMonitor(pool).check(ctx)
	NewInsiderThreatDetector(pool, nc).detect(ctx)
	NewLicenseExpiryNotifier(pool).check(ctx)
	NewNetworkAnomalyDetector(pool, nc).detect(ctx)
	NewRealtimeCorrelator(pool, nc).loadRules(ctx)
	NewRetroIOCHunter(pool, nc, 7, 0).hunt(ctx)
}
