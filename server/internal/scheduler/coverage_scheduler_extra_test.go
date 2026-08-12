package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/behavioral"
	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/store"
)

// stubRuleEvaluator satisfies the hunter's ruleEvaluator with no matches.
type stubRuleEvaluator struct{}

func (stubRuleEvaluator) Evaluate(ctx context.Context, evt interface{}) ([]*detectionrules.RuleMatch, error) {
	return nil, nil
}

// Drives a second wave of scheduler workers (their one-shot passes) against the
// migrated schema, complementing TestScheduler_Workers.
func TestScheduler_ExtraWorkers(t *testing.T) {
	db := covSchedDB(t)
	pool := db.Pool()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed an agent + process event so the retro hunter traverses its per-row
	// re-evaluation loop.
	var agentID string
	_ = pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-sched2', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID)
	if agentID != "" {
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })
		_, _ = pool.Exec(ctx,
			`INSERT INTO events (agent_id, event_type, raw_data, time)
			 VALUES ($1::uuid, 'process', '{"process_name":"sh","command_line":"sh -c x"}'::jsonb, NOW())`, agentID)
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM events WHERE agent_id=$1", agentID) })
	}

	NewBaselineRebuilder(pool, behavioral.NewEngine(pool)).rebuild(ctx)
	NewDailyBriefingScheduler(pool, 8, nil, "", "").collect(ctx)
	NewReportScheduler(store.NewReportScheduleStore(db), pool).processDue(ctx)
	NewRetroRuleHunter(pool, stubRuleEvaluator{}, 24, 0).hunt(ctx)
}
