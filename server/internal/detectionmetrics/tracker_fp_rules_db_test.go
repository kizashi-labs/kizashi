//go:build integration

package detectionmetrics

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestTopFalsePositiveRulesReturnsRows is the regression gate for a dormant bug
// this package shipped with: the "top false positive rules" query selected and
// grouped by a column `rule_name` that has never existed on `alerts`. Postgres
// answered SQLSTATE 42703 on every call, the error was assigned to `err`, the
// `if err == nil` guard skipped the whole result block, and the API returned an
// empty list. No log line, no failing test, no visible symptom — the feature had
// simply never worked.
//
// Pure-logic tests could not see it, because the defect lives in SQL that only a
// real database rejects. This test drives the actual query against a migrated
// schema and asserts rows come back, so a future edit that renames or drops the
// grouping column fails loudly instead of silently emptying the dashboard.
func TestTopFalsePositiveRulesReturnsRows(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set — skipping DB-backed FP-rules test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("cannot connect to DATABASE_URL: %v", err)
	}
	// defer ではなく t.Cleanup。defer はテスト関数の return 時に走るため、
	// その後に走る t.Cleanup の DELETE が閉じたプールに当たってしまう。
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB ping failed: %v", err)
	}

	// A minimal agent + two alerts on the same title, one labelled as a false
	// positive — exactly the shape an FP soak produces via fpsoak-report -label.
	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, status)
		VALUES ('fpmetrics-test-host', 'linux', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Skipf("agents table unavailable (unmigrated schema?): %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM agents WHERE id = $1::uuid`, agentID); err != nil {
			t.Errorf("後片付けに失敗しました (agents): %v", err)
		}
	})

	const title = "fpmetrics-test-rule"
	for _, status := range []string{"false_positive", "open"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, severity, status, title, created_at)
			VALUES ($1::uuid, 5, $2, $3, NOW())`, agentID, status, title); err != nil {
			t.Fatalf("alert insert failed (%s): %v", status, err)
		}
	}

	m, err := NewTracker(pool).Calculate(ctx, "24h")
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}

	var found *RuleStat
	for i := range m.TopFalsePositiveRules {
		if m.TopFalsePositiveRules[i].RuleName == title {
			found = &m.TopFalsePositiveRules[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("the seeded false positive is missing from TopFalsePositiveRules "+
			"(len=%d) — the query is failing silently again",
			len(m.TopFalsePositiveRules))
	}
	if found.FPCount != 1 {
		t.Errorf("fp_count = %d, want 1", found.FPCount)
	}
	if found.TotalCount != 2 {
		t.Errorf("total_count = %d, want 2", found.TotalCount)
	}
	if found.FPRate != 0.5 {
		t.Errorf("fp_rate = %v, want 0.5", found.FPRate)
	}
}
