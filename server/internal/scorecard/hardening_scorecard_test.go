package scorecard

import (
	"context"
	"testing"
)

// TestScorer_HardeningControl proves the #5 fix: the endpoint-configuration
// baseline control (PR.IP-1) now scores from real endpoint_hardening_baselines
// / endpoint_hardening_assessments rows (the tables the agent's hardening
// reporter populates) rather than always reporting non_compliant.
func TestScorer_HardeningControl(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-hard', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var baselineID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO hardening_baselines (name, os_type, framework)
		 VALUES ('cov-hardening-test', 'linux', 'cis') RETURNING id::text`).Scan(&baselineID); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM hardening_assessments WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM hardening_baselines WHERE id=$1", baselineID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	// 3 passed, 1 failed → 75% compliance.
	if _, err := pool.Exec(ctx,
		`INSERT INTO hardening_assessments
		   (baseline_id, agent_id, passed_checks, failed_checks, score, status)
		 VALUES ($1::uuid, $2::uuid, 3, 1, 75, 'completed')`,
		baselineID, agentID); err != nil {
		t.Fatalf("seed assessment: %v", err)
	}

	sc, err := NewScorer(pool).CalculateNISTCSF(ctx)
	if err != nil {
		t.Fatalf("CalculateNISTCSF: %v", err)
	}
	var ctrl *Control
	for _, c := range sc.Controls {
		if c.ID == "PR.IP-1" {
			ctrl = c
		}
	}
	if ctrl == nil {
		t.Fatalf("PR.IP-1 control missing")
	}
	// With baselines present the control leaves the non_compliant (30) branch and
	// scores from the pass-rate; > 30 is sufficient to prove the tables are read.
	if ctrl.Score <= 30 {
		t.Fatalf("hardening control did not score from seeded baselines: %+v", ctrl)
	}
}
