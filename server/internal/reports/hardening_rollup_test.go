package reports

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The compliance report's per-control table read endpoint_hardening_assessments,
// which migration 363 created and 364 dropped when it consolidated onto
// hardening_assessments. The reader was never moved, so every compliance report
// generated since 364 has been built from an empty result set — the query
// failed with 42P01, the failure was logged and the report carried on with no
// controls at all.
//
// Moving it was not a table rename. The consolidated table keeps one row per
// ASSESSMENT with the per-check outcomes inside a findings jsonb array, where
// the old one kept one row per CHECK. The roll-up unnests it.

func rollupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The headline: two agents assessed against the same checks roll up into one
// row per check with the right pass/fail split. One row per assessment would
// give the wrong shape entirely.
func TestTheComplianceRollupCountsChecksAcrossAssessments(t *testing.T) {
	pool := rollupPool(t)
	ctx := context.Background()

	marker := "rollup-" + uuid.NewString()[:8]
	var baselineID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO hardening_baselines (name, description, os_type, framework, version, checks, enabled)
		VALUES ($1, 'fixture', 'all', 'cis', 'v1', '[]'::jsonb, true)
		RETURNING id`, marker).Scan(&baselineID); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM hardening_assessments WHERE baseline_id=$1`, baselineID)
		_, _ = pool.Exec(c, `DELETE FROM hardening_baselines WHERE id=$1`, baselineID)
	})

	// Two agents, same two checks: firewall passes on both, bitlocker on one.
	for _, bitlocker := range []bool{true, false} {
		agentID := uuid.NewString()
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (id,hostname,os_type,status,last_seen)
			 VALUES ($1::uuid,$2,'windows','online',NOW())`, agentID, marker); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
		})
		raw, _ := json.Marshal([]map[string]any{
			{"id": marker + "-firewall", "title": marker + " Firewall", "passed": true},
			{"id": marker + "-bitlocker", "title": marker + " BitLocker", "passed": bitlocker},
		})
		if _, err := pool.Exec(ctx, `
			INSERT INTO hardening_assessments
			  (baseline_id, agent_id, passed_checks, failed_checks, skipped_checks, score, status, findings, assessed_at)
			VALUES ($1, $2::uuid, 0, 0, 0, 0, 'completed', $3::jsonb, NOW())`,
			baselineID, agentID, string(raw)); err != nil {
			t.Fatalf("seed assessment: %v", err)
		}
	}

	// Exercised through the generator rather than by re-issuing its query here.
	// A test that writes out the statement it is checking passes whatever the
	// generator does: the first version of this one did exactly that, and a
	// mutation that stopped unnesting the findings survived it.
	data, err := NewGenerator(pool).GenerateComplianceReport(ctx, &ReportSpec{
		Type: "compliance_report",
		DateRange: DateRange{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now().Add(1 * time.Hour),
		},
	})
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}

	// The table is shared, so pick out this fixture's own controls.
	got := map[string][2]int{}
	for _, ctrl := range data.Controls {
		if strings.HasPrefix(ctrl.ControlName, marker) {
			got[ctrl.ControlName] = [2]int{ctrl.Passed, ctrl.Failed}
		}
	}

	if len(got) != 2 {
		t.Fatalf("チェック項目が %d 件です (2件を期待): %v。"+
			"1評価=1行のままだとチェック単位に展開されません", len(got), got)
	}
	if v := got[marker+" Firewall"]; v != [2]int{2, 0} {
		t.Errorf("Firewall = 合格%d/不合格%d, want 2/0", v[0], v[1])
	}
	if v := got[marker+" BitLocker"]; v != [2]int{1, 1} {
		t.Errorf("BitLocker = 合格%d/不合格%d, want 1/1。"+
			"2台の端末で結果が割れている項目です", v[0], v[1])
	}
}
