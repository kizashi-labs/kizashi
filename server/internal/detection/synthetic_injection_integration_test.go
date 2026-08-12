//go:build integration

package detection

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSyntheticInjectionE2E drives synthetic NormalizedEvents through the REAL
// AlertPipeline.handleEvent path (flatten → Sigma field alias → evaluate →
// INSERT into the real alerts table) and asserts an alert row is actually
// persisted to PostgreSQL.
//
// This is the regression gate for the "silent break" class — an event flows in
// but no alert comes out — which the pure-logic oracle tests (EvaluateEnvelope,
// field_support_audit) cannot fully catch because they stop before the DB. Two
// historical break modes only a real INSERT reproduces:
//   - field alias missing  → the rule goes inert (no match, no alert)
//   - DB-constraint failure → non-UUID rule_id (SQLSTATE 22P02), CHECK violation,
//     or param-cast 42P08 make the INSERT fail silently (logged, no row)
//
// Requires DATABASE_URL to point at a migrated schema. Skips (does not fail)
// when the DB is unreachable or unmigrated, matching the integration-suite
// philosophy; the actual "injected but no alert" assertion is a hard failure.
func TestSyntheticInjectionE2E(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set — skipping synthetic injection E2E")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("cannot connect to DATABASE_URL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB ping failed: %v", err)
	}

	// Seed a throwaway agent: alerts.agent_id has an FK to agents(id), and the
	// insert path casts agent_id to ::uuid, so we need a real UUID that exists.
	var agentID string
	err = pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, tenant_id)
		VALUES ('e2e-synth-injection', 'windows', '00000000-0000-0000-0000-000000000001')
		RETURNING id`).Scan(&agentID)
	if err != nil {
		t.Skipf("cannot seed agent (schema not migrated?): %v", err)
	}
	// ON DELETE CASCADE removes the alerts we create below.
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) }()

	// nil NATS conn: publishing is best-effort and nil-guarded; the insert path is
	// what we exercise. remediation/correlation are nil, so handleEvent's DB write
	// is synchronous.
	p := NewAlertPipeline(pool, nil)
	LoadBuiltinRules(p.sigma)

	// Each case is a synthetic NormalizedEvent (exact agent wire form) known to
	// fire a built-in Sigma rule once flattened + aliased. Different rules per
	// case so the 5-minute dedup never collides. Registry exercises the
	// highest-risk alias chain (key_path/value_data → TargetObject/Details).
	cases := []struct {
		name  string
		etype string
		event string
	}{
		{
			name:  "registry_run_key_persistence",
			etype: "registry",
			event: `{"agent_id":"` + agentID + `","hostname":"e2e-synth-injection","platform":"windows","type":"registry","data":{"key_path":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","value_name":"Updater","value_data":"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe","operation":"modify"}}`,
		},
		{
			name:  "file_etc_passwd_write",
			etype: "file",
			event: `{"agent_id":"` + agentID + `","hostname":"e2e-synth-injection","platform":"linux","type":"file","data":{"path":"/etc/passwd","action":"modify"}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := countAlerts(t, ctx, pool, agentID)

			p.handleEvent(ctx, "events."+agentID+"."+tc.etype, []byte(tc.event))

			// The insert is synchronous, but poll briefly to be robust.
			after := before
			for i := 0; i < 20 && after <= before; i++ {
				time.Sleep(50 * time.Millisecond)
				after = countAlerts(t, ctx, pool, agentID)
			}
			if after <= before {
				t.Fatalf("%s: an event was injected but no alert row was persisted "+
					"(silent break — field alias missing or INSERT failed)", tc.name)
			}
		})
	}
}

func countAlerts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}
