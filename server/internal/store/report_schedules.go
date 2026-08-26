package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportSchedule defines a recurring report generation task.
type ReportSchedule struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	ReportType    string     `json:"report_type"`
	Frequency     string     `json:"frequency"` // daily | weekly | monthly
	DayOfWeek     *int       `json:"day_of_week,omitempty"`
	DayOfMonth    *int       `json:"day_of_month,omitempty"`
	Hour          int        `json:"hour"`
	Recipients    []string   `json:"recipients"`
	IsActive      bool       `json:"is_active"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	NextRunAt     time.Time  `json:"next_run_at"`
	CreatedBy     *string    `json:"created_by,omitempty"`
	CreatedByName string     `json:"created_by_name,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ReportScheduleStore manages scheduled report persistence.
type ReportScheduleStore struct {
	pool *pgxpool.Pool
}

func NewReportScheduleStore(db *DB) *ReportScheduleStore {
	return &ReportScheduleStore{pool: db.Pool()}
}

func scanSchedule(sc *ReportSchedule, rows interface {
	Scan(...interface{}) error
}) error {
	var createdBy *string
	var recipients []string
	err := rows.Scan(
		&sc.ID, &sc.Name, &sc.ReportType, &sc.Frequency,
		&sc.DayOfWeek, &sc.DayOfMonth, &sc.Hour,
		&recipients, &sc.IsActive,
		&sc.LastRunAt, &sc.NextRunAt,
		&createdBy, &sc.CreatedByName,
		&sc.CreatedAt, &sc.UpdatedAt,
	)
	if err != nil {
		return err
	}
	sc.Recipients = recipients
	if sc.Recipients == nil {
		sc.Recipients = []string{}
	}
	sc.CreatedBy = createdBy
	return nil
}

const scheduleSelectSQL = `
	SELECT rs.id, rs.name, rs.report_type, rs.frequency,
	       rs.day_of_week, rs.day_of_month, rs.hour,
	       rs.recipients, rs.is_active,
	       rs.last_run_at, rs.next_run_at,
	       rs.created_by::text,
	       COALESCE(NULLIF(u.full_name,''), u.email, ''),
	       rs.created_at, rs.updated_at
	FROM report_schedules rs
	LEFT JOIN users u ON u.id = rs.created_by`

// List returns all schedules newest-first.
func (s *ReportScheduleStore) List(ctx context.Context) ([]*ReportSchedule, error) {
	rows, err := s.pool.Query(ctx, scheduleSelectSQL+`
		ORDER BY rs.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []*ReportSchedule
	for rows.Next() {
		sc := &ReportSchedule{}
		if err := scanSchedule(sc, rows); err != nil {
			continue
		}
		schedules = append(schedules, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if schedules == nil {
		schedules = []*ReportSchedule{}
	}
	return schedules, nil
}

// Insert creates a new schedule, returns the new ID.
func (s *ReportScheduleStore) Insert(ctx context.Context, sc *ReportSchedule) (string, error) {
	if sc.Recipients == nil {
		sc.Recipients = []string{}
	}
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO report_schedules
		  (name, report_type, frequency, day_of_week, day_of_month, hour,
		   recipients, is_active, next_run_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid)
		RETURNING id`,
		sc.Name, sc.ReportType, sc.Frequency,
		sc.DayOfWeek, sc.DayOfMonth, sc.Hour,
		sc.Recipients, sc.IsActive, sc.NextRunAt,
		nilIfEmpty(sc.CreatedBy),
	).Scan(&id)
	return id, err
}

// Update replaces a schedule's editable fields.
func (s *ReportScheduleStore) Update(ctx context.Context, sc *ReportSchedule) error {
	if sc.Recipients == nil {
		sc.Recipients = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE report_schedules
		SET name=$2, report_type=$3, frequency=$4,
		    day_of_week=$5, day_of_month=$6, hour=$7,
		    recipients=$8, is_active=$9, next_run_at=$10, updated_at=NOW()
		WHERE id=$1`,
		sc.ID, sc.Name, sc.ReportType, sc.Frequency,
		sc.DayOfWeek, sc.DayOfMonth, sc.Hour,
		sc.Recipients, sc.IsActive, sc.NextRunAt,
	)
	return err
}

// Delete removes a schedule.
func (s *ReportScheduleStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM report_schedules WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// SetActive toggles the is_active flag.
func (s *ReportScheduleStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE report_schedules SET is_active=$2, updated_at=NOW() WHERE id=$1",
		id, active,
	)
	return err
}

// GetDue returns active schedules whose next_run_at has passed.
func (s *ReportScheduleStore) GetDue(ctx context.Context) ([]*ReportSchedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rs.id, rs.name, rs.report_type, rs.frequency,
		       rs.day_of_week, rs.day_of_month, rs.hour,
		       rs.recipients, rs.is_active,
		       rs.last_run_at, rs.next_run_at,
		       rs.created_by::text,
		       '',
		       rs.created_at, rs.updated_at
		FROM report_schedules rs
		WHERE rs.is_active = TRUE AND rs.next_run_at <= NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []*ReportSchedule
	for rows.Next() {
		sc := &ReportSchedule{}
		if err := scanSchedule(sc, rows); err != nil {
			continue
		}
		schedules = append(schedules, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return schedules, nil
}

// MarkRun updates last_run_at and schedules the next run.
func (s *ReportScheduleStore) MarkRun(ctx context.Context, id string, nextRun time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE report_schedules
		SET last_run_at=NOW(), next_run_at=$2, updated_at=NOW()
		WHERE id=$1`,
		id, nextRun,
	)
	return err
}

// ComputeNextRun calculates the next scheduled run time after the given instant.
func ComputeNextRun(sc *ReportSchedule, after time.Time) time.Time {
	base := time.Date(after.Year(), after.Month(), after.Day(), sc.Hour, 0, 0, 0, time.UTC)

	switch sc.Frequency {
	case "daily":
		next := base
		if !next.After(after) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case "weekly":
		dow := 0
		if sc.DayOfWeek != nil {
			dow = *sc.DayOfWeek
		}
		next := base
		for int(next.Weekday()) != dow || !next.After(after) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case "monthly":
		dom := 1
		if sc.DayOfMonth != nil {
			dom = *sc.DayOfMonth
		}
		next := time.Date(after.Year(), after.Month(), dom, sc.Hour, 0, 0, 0, time.UTC)
		if !next.After(after) {
			next = time.Date(after.Year(), after.Month()+1, dom, sc.Hour, 0, 0, 0, time.UTC)
		}
		return next
	default:
		return after.Add(24 * time.Hour)
	}
}
