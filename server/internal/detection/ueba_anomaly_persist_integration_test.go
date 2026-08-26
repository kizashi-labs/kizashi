//go:build integration

package detection

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSaveUEBAAnomalyPersists is the regression gate for a silent-failure bug:
// saveUEBAAnomaly wrote only the columns migration 205 added, while migration
// 121 had created ueba_anomalies with username/anomaly_type/score as NOT NULL
// and no defaults. Every insert therefore failed with
//
//	null value in column "username" of relation "ueba_anomalies"
//
// and UEBA anomalies were never persisted — which silently emptied everything
// insider_threat_handler.go derives from that table (risk scores, high-risk user
// counts, threat categories). The failure logged at Debug level with the guess
// "table may not exist", so nothing surfaced it; the FP soak only found it by
// flooding a CI postgres log with ~700 copies of the constraint violation.
//
// A pure-logic test cannot catch this: the SQL is only rejected by a real
// database. Hence the integration tag.
func TestSaveUEBAAnomalyPersists(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set — skipping UEBA anomaly persistence test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("cannot connect to DATABASE_URL: %v", err)
	}
	// t.Cleanup, not defer: cleanup functions run AFTER the test function
	// returns, so a deferred Close has already happened by the time they run and
	// every statement they issue fails with "closed pool" into a discarded error.
	// Registering the Close first makes it run last (cleanups are LIFO), which is
	// the order the data cleanups below need.
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB ping failed: %v", err)
	}

	var agentID string
	err = pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, tenant_id)
		VALUES ('ueba-persist-test', 'linux', '00000000-0000-0000-0000-000000000001')
		RETURNING id`).Scan(&agentID)
	if err != nil {
		t.Skipf("cannot seed agent (schema not migrated?): %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx,
			`DELETE FROM ueba_anomalies WHERE user_key = 'ueba-persist-user'`); err != nil {
			t.Errorf("後片付けに失敗しました (ueba_anomalies): %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID); err != nil {
			t.Errorf("後片付けに失敗しました (agents): %v", err)
		}
	})

	p := &AlertPipeline{pool: pool}
	p.saveUEBAAnomaly(ctx, "ueba-persist-user", "process_spawn_rate",
		AnomalyResult{Baseline: 4, Actual: 91, ZScore: 7.5, Severity: "high"},
		map[string]interface{}{"agent_id": agentID})

	// Both column generations must be populated: the two handler families read
	// different ones, so filling only one set leaves half the UI empty.
	var username, anomalyType, userKey, metricName string
	var score, zScore float64
	err = pool.QueryRow(ctx, `
		SELECT username, anomaly_type, score, user_key, metric_name, z_score
		FROM ueba_anomalies WHERE user_key = 'ueba-persist-user'`).
		Scan(&username, &anomalyType, &score, &userKey, &metricName, &zScore)
	if err != nil {
		t.Fatalf("UEBA異常が永続化されていません: %v", err)
	}

	if username != "ueba-persist-user" || userKey != username {
		t.Errorf("username=%q user_key=%q — 両方に同じ値が入るべきです", username, userKey)
	}
	if anomalyType != "process_spawn_rate" || metricName != anomalyType {
		t.Errorf("anomaly_type=%q metric_name=%q", anomalyType, metricName)
	}
	if score != zScore {
		t.Errorf("score=%v z_score=%v — 同じ値が入るべきです", score, zScore)
	}
}
