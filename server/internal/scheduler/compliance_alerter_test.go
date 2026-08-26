package scheduler

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestComplianceAlerter_RaisesAndDedupes proves the posture alerter turns an
// unencrypted endpoint and a failing hardening assessment into open alerts, and
// that a second pass does not duplicate them.
func TestComplianceAlerter_RaisesAndDedupes(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping compliance alerter test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	// t.Cleanup, not defer: cleanup functions run AFTER the test function
	// returns, so a deferred Close has already happened by the time they run and
	// every statement they issue fails with "closed pool" into a discarded error.
	// Registering the Close first makes it run last (cleanups are LIFO), which is
	// the order the data cleanups below need.
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('compl-alert-host', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var baselineID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO hardening_baselines (name, os_type, framework)
		 VALUES ('compl-alert-baseline', 'linux', 'cis') RETURNING id::text`).Scan(&baselineID); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	// 後片付けが失敗すると次回以降 uq_hardening_baselines_name に当たって
	// このテストが落ちる。黙って捨てず、失敗を残す。
	t.Cleanup(func() {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"DELETE FROM alerts WHERE agent_id=$1", []any{agentID}},
			{"DELETE FROM hardening_assessments WHERE agent_id=$1", []any{agentID}},
			{"DELETE FROM hardening_baselines WHERE id=$1", []any{baselineID}},
			{"DELETE FROM endpoint_encryption WHERE agent_id=$1", []any{agentID}},
			{"DELETE FROM agents WHERE id=$1", []any{agentID}},
		} {
			if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Errorf("後片付けに失敗しました (%s): %v", q.sql, err)
			}
		}
	})

	// Unencrypted endpoint.
	if _, err := pool.Exec(ctx,
		`INSERT INTO endpoint_encryption (agent_id, encrypted, method) VALUES ($1::uuid, FALSE, 'LUKS')`,
		agentID); err != nil {
		t.Fatalf("seed encryption: %v", err)
	}
	// Failing hardening assessment (40% < threshold).
	if _, err := pool.Exec(ctx,
		`INSERT INTO hardening_assessments
		   (baseline_id, agent_id, passed_checks, failed_checks, score, status, assessed_at)
		 VALUES ($1::uuid, $2::uuid, 2, 3, 40, 'completed', NOW())`,
		baselineID, agentID); err != nil {
		t.Fatalf("seed assessment: %v", err)
	}

	alerter := NewComplianceAlerter(pool, nil)
	alerter.check(ctx)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id=$1::uuid AND source='compliance_posture'`,
		agentID).Scan(&count); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 compliance alerts (encryption + hardening), got %d", count)
	}

	// Second pass must not duplicate within the dedup window.
	alerter.check(ctx)
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id=$1::uuid AND source='compliance_posture'`,
		agentID).Scan(&count); err != nil {
		t.Fatalf("recount alerts: %v", err)
	}
	if count != 2 {
		t.Fatalf("dedup failed: expected 2 alerts after second pass, got %d", count)
	}
}
