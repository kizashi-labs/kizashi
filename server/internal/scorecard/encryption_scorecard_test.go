package scorecard

import (
	"context"
	"testing"
)

// TestScorer_EncryptionControl proves the #4 fix: the data-at-rest protection
// control (PR.DS-1) now counts rows from endpoint_encryption (the table the
// agent's encryption reporter populates) rather than always reporting the
// "no data" partial score, so it reflects real endpoint encryption state.
func TestScorer_EncryptionControl(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-enc', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM endpoint_encryption WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO endpoint_encryption (agent_id, encrypted, method, details)
		 VALUES ($1::uuid, TRUE, 'LUKS', 'dm-0')`, agentID); err != nil {
		t.Fatalf("seed encryption: %v", err)
	}

	sc, err := NewScorer(pool).CalculateNISTCSF(ctx)
	if err != nil {
		t.Fatalf("CalculateNISTCSF: %v", err)
	}
	var ctrl *Control
	for _, c := range sc.Controls {
		if c.ID == "PR.DS-1" {
			ctrl = c
		}
	}
	if ctrl == nil {
		t.Fatalf("PR.DS-1 control missing")
	}
	// With a seeded endpoint_encryption row the control reaches its "compliant"
	// branch (score 80) instead of the empty-table partial score (40).
	if ctrl.Score < 80 {
		t.Fatalf("encryption control did not score compliant with seeded endpoint_encryption: %+v", ctrl)
	}
}
