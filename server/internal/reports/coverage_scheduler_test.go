package reports

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covSchedPool connects to TEST_DATABASE_URL (the migrated schema), skipping
// when unset so pure-logic runs stay green. Drives the scheduled-report CRUD
// lifecycle plus the parseCron/isDue helpers.
func covSchedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping reports scheduler coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestScheduler_CRUD_DB(t *testing.T) {
	pool := covSchedPool(t)
	s := NewScheduler(pool, NewGenerator(pool), nil)
	ctx := context.Background()

	rep := &ScheduledReport{
		Name: "cov-sched-report", ReportType: "executive_summary",
		Schedule: "0 8 * * 1", Format: "json",
		Recipients: []string{"cov@example.com"}, Enabled: true,
	}
	if err := s.AddSchedule(ctx, rep); err != nil {
		t.Fatalf("AddSchedule: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM scheduled_reports WHERE id=$1", rep.ID) })

	if _, err := s.ListSchedules(ctx); err != nil {
		t.Fatalf("ListSchedules: %v", err)
	}
	rep.Name = "cov-sched-report-2"
	if err := s.UpdateSchedule(ctx, rep); err != nil {
		t.Fatalf("UpdateSchedule: %v", err)
	}
	if err := s.ToggleSchedule(ctx, rep.ID, false); err != nil {
		t.Fatalf("ToggleSchedule: %v", err)
	}
	s.LoadFromDB(ctx)
	if err := s.RemoveSchedule(ctx, rep.ID); err != nil {
		t.Fatalf("RemoveSchedule: %v", err)
	}
}
