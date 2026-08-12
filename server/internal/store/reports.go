package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportJobRow mirrors the report_jobs table.
type ReportJobRow struct {
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	Status          string      `json:"status"`
	RequestedBy     string      `json:"requested_by"`
	RequestedByName string      `json:"requested_by_name,omitempty"`
	RequestedAt     time.Time   `json:"requested_at"`
	CompletedAt     *time.Time  `json:"completed_at,omitempty"`
	FromTime        *time.Time  `json:"from_time,omitempty"`
	ToTime          *time.Time  `json:"to_time,omitempty"`
	Error           string      `json:"error,omitempty"`
	Content         interface{} `json:"content,omitempty"`
}

// ReportStore manages report job persistence.
type ReportStore struct {
	pool *pgxpool.Pool
}

func NewReportStore(db *DB) *ReportStore {
	return &ReportStore{pool: db.Pool()}
}

// Insert creates a new report job row with status=pending.
func (s *ReportStore) Insert(ctx context.Context, job *ReportJobRow) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO report_jobs (id, type, status, requested_by, from_time, to_time)
		VALUES ($1, $2, 'pending', $3, $4, $5)`,
		job.ID, job.Type, job.RequestedBy, job.FromTime, job.ToTime,
	)
	return err
}

// SetRunning marks a job as running.
func (s *ReportStore) SetRunning(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE report_jobs SET status = 'running' WHERE id = $1", id)
	return err
}

// Complete marks a job as completed and stores its content.
func (s *ReportStore) Complete(ctx context.Context, id string, content interface{}) error {
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE report_jobs
		SET status = 'completed', completed_at = NOW(), content = $2
		WHERE id = $1`,
		id, string(contentJSON),
	)
	return err
}

// Fail marks a job as failed with an error message.
func (s *ReportStore) Fail(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE report_jobs
		SET status = 'failed', completed_at = NOW(), error = $2
		WHERE id = $1`,
		id, errMsg,
	)
	return err
}

// Get retrieves a single report job.
func (s *ReportStore) Get(ctx context.Context, id string) (*ReportJobRow, error) {
	var job ReportJobRow
	var contentJSON *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, type, status, COALESCE(requested_by,''),
		       requested_at, completed_at, from_time, to_time,
		       COALESCE(error,''), content::text
		FROM report_jobs WHERE id = $1`, id,
	).Scan(
		&job.ID, &job.Type, &job.Status, &job.RequestedBy,
		&job.RequestedAt, &job.CompletedAt, &job.FromTime, &job.ToTime,
		&job.Error, &contentJSON,
	)
	if err != nil {
		return nil, err
	}
	if contentJSON != nil {
		var v interface{}
		_ = json.Unmarshal([]byte(*contentJSON), &v)
		job.Content = v
	}
	return &job, nil
}

// Delete removes a report job and its content.
func (s *ReportStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM report_jobs WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// List returns all report jobs newest-first, including the requester's display name.
func (s *ReportStore) List(ctx context.Context) ([]*ReportJobRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rj.id, rj.type, rj.status, COALESCE(rj.requested_by,''),
		       rj.requested_at, rj.completed_at, rj.from_time, rj.to_time,
		       COALESCE(rj.error,''),
		       COALESCE(NULLIF(u.full_name,''), u.email, '')
		FROM report_jobs rj
		LEFT JOIN users u ON u.id::text = rj.requested_by::text
		ORDER BY rj.requested_at DESC
		LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*ReportJobRow
	for rows.Next() {
		var job ReportJobRow
		if err := rows.Scan(
			&job.ID, &job.Type, &job.Status, &job.RequestedBy,
			&job.RequestedAt, &job.CompletedAt, &job.FromTime, &job.ToTime,
			&job.Error, &job.RequestedByName,
		); err != nil {
			continue
		}
		jobs = append(jobs, &job)
	}
	return jobs, nil
}
