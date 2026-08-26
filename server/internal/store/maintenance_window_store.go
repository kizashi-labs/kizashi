package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaintenanceWindow represents a scheduled maintenance period.
type MaintenanceWindow struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	StartTime             time.Time `json:"start_time"`
	EndTime               time.Time `json:"end_time"`
	Recurring             bool      `json:"recurring"`
	RecurrencePattern     string    `json:"recurrence_pattern"`
	SuppressAlerts        bool      `json:"suppress_alerts"`
	SuppressNotifications bool      `json:"suppress_notifications"`
	AffectedAgents        []string  `json:"affected_agents"`
	AffectedGroups        []string  `json:"affected_groups"`
	Enabled               bool      `json:"enabled"`
	CreatedBy             *string   `json:"created_by,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// MaintenanceWindowStore handles maintenance window persistence.
type MaintenanceWindowStore struct {
	pool *pgxpool.Pool
}

// NewMaintenanceWindowStore creates a new MaintenanceWindowStore.
func NewMaintenanceWindowStore(pool *pgxpool.Pool) *MaintenanceWindowStore {
	return &MaintenanceWindowStore{pool: pool}
}

// List returns all maintenance windows ordered by start_time DESC.
func (s *MaintenanceWindowStore) List(ctx context.Context) ([]*MaintenanceWindow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''),
		       start_time, end_time,
		       recurring, COALESCE(recurrence_pattern,''),
		       suppress_alerts, suppress_notifications,
		       COALESCE(affected_agents, '{}'), COALESCE(affected_groups, '{}'),
		       enabled, created_by::text,
		       created_at, updated_at
		FROM maintenance_windows
		ORDER BY start_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []*MaintenanceWindow
	for rows.Next() {
		w := &MaintenanceWindow{}
		var createdBy *string
		if err := rows.Scan(
			&w.ID, &w.Name, &w.Description,
			&w.StartTime, &w.EndTime,
			&w.Recurring, &w.RecurrencePattern,
			&w.SuppressAlerts, &w.SuppressNotifications,
			&w.AffectedAgents, &w.AffectedGroups,
			&w.Enabled, &createdBy,
			&w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			continue
		}
		w.CreatedBy = createdBy
		if w.AffectedAgents == nil {
			w.AffectedAgents = []string{}
		}
		if w.AffectedGroups == nil {
			w.AffectedGroups = []string{}
		}
		windows = append(windows, w)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if windows == nil {
		windows = []*MaintenanceWindow{}
	}
	return windows, nil
}

// Create inserts a new maintenance window and returns the created record.
func (s *MaintenanceWindowStore) Create(ctx context.Context, w *MaintenanceWindow) (*MaintenanceWindow, error) {
	if w.AffectedAgents == nil {
		w.AffectedAgents = []string{}
	}
	if w.AffectedGroups == nil {
		w.AffectedGroups = []string{}
	}

	var created MaintenanceWindow
	var createdBy *string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO maintenance_windows
		  (name, description, start_time, end_time,
		   recurring, recurrence_pattern,
		   suppress_alerts, suppress_notifications,
		   affected_agents, affected_groups,
		   enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::uuid)
		RETURNING id, name, COALESCE(description,''),
		          start_time, end_time,
		          recurring, COALESCE(recurrence_pattern,''),
		          suppress_alerts, suppress_notifications,
		          COALESCE(affected_agents,'{}'), COALESCE(affected_groups,'{}'),
		          enabled, created_by::text,
		          created_at, updated_at`,
		w.Name, w.Description, w.StartTime, w.EndTime,
		w.Recurring, w.RecurrencePattern,
		w.SuppressAlerts, w.SuppressNotifications,
		w.AffectedAgents, w.AffectedGroups,
		w.Enabled, nilIfEmpty(w.CreatedBy),
	).Scan(
		&created.ID, &created.Name, &created.Description,
		&created.StartTime, &created.EndTime,
		&created.Recurring, &created.RecurrencePattern,
		&created.SuppressAlerts, &created.SuppressNotifications,
		&created.AffectedAgents, &created.AffectedGroups,
		&created.Enabled, &createdBy,
		&created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	created.CreatedBy = createdBy
	if created.AffectedAgents == nil {
		created.AffectedAgents = []string{}
	}
	if created.AffectedGroups == nil {
		created.AffectedGroups = []string{}
	}
	return &created, nil
}

// Get retrieves a single maintenance window by ID.
func (s *MaintenanceWindowStore) Get(ctx context.Context, id string) (*MaintenanceWindow, error) {
	w := &MaintenanceWindow{}
	var createdBy *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''),
		       start_time, end_time,
		       recurring, COALESCE(recurrence_pattern,''),
		       suppress_alerts, suppress_notifications,
		       COALESCE(affected_agents,'{}'), COALESCE(affected_groups,'{}'),
		       enabled, created_by::text,
		       created_at, updated_at
		FROM maintenance_windows
		WHERE id = $1`, id,
	).Scan(
		&w.ID, &w.Name, &w.Description,
		&w.StartTime, &w.EndTime,
		&w.Recurring, &w.RecurrencePattern,
		&w.SuppressAlerts, &w.SuppressNotifications,
		&w.AffectedAgents, &w.AffectedGroups,
		&w.Enabled, &createdBy,
		&w.CreatedAt, &w.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("not found")
	}
	w.CreatedBy = createdBy
	if w.AffectedAgents == nil {
		w.AffectedAgents = []string{}
	}
	if w.AffectedGroups == nil {
		w.AffectedGroups = []string{}
	}
	return w, nil
}

// Update modifies an existing maintenance window by ID.
func (s *MaintenanceWindowStore) Update(ctx context.Context, id string, w *MaintenanceWindow) (*MaintenanceWindow, error) {
	if w.AffectedAgents == nil {
		w.AffectedAgents = []string{}
	}
	if w.AffectedGroups == nil {
		w.AffectedGroups = []string{}
	}

	var updated MaintenanceWindow
	var createdBy *string
	err := s.pool.QueryRow(ctx, `
		UPDATE maintenance_windows
		SET name = $2, description = $3,
		    start_time = $4, end_time = $5,
		    recurring = $6, recurrence_pattern = $7,
		    suppress_alerts = $8, suppress_notifications = $9,
		    affected_agents = $10, affected_groups = $11,
		    enabled = $12, updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, COALESCE(description,''),
		          start_time, end_time,
		          recurring, COALESCE(recurrence_pattern,''),
		          suppress_alerts, suppress_notifications,
		          COALESCE(affected_agents,'{}'), COALESCE(affected_groups,'{}'),
		          enabled, created_by::text,
		          created_at, updated_at`,
		id,
		w.Name, w.Description,
		w.StartTime, w.EndTime,
		w.Recurring, w.RecurrencePattern,
		w.SuppressAlerts, w.SuppressNotifications,
		w.AffectedAgents, w.AffectedGroups,
		w.Enabled,
	).Scan(
		&updated.ID, &updated.Name, &updated.Description,
		&updated.StartTime, &updated.EndTime,
		&updated.Recurring, &updated.RecurrencePattern,
		&updated.SuppressAlerts, &updated.SuppressNotifications,
		&updated.AffectedAgents, &updated.AffectedGroups,
		&updated.Enabled, &createdBy,
		&updated.CreatedAt, &updated.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("not found")
	}
	updated.CreatedBy = createdBy
	if updated.AffectedAgents == nil {
		updated.AffectedAgents = []string{}
	}
	if updated.AffectedGroups == nil {
		updated.AffectedGroups = []string{}
	}
	return &updated, nil
}

// Delete removes a maintenance window by ID.
func (s *MaintenanceWindowStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM maintenance_windows WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// IsActive returns true if any enabled maintenance window is currently active.
func (s *MaintenanceWindowStore) IsActive(ctx context.Context) (bool, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM maintenance_windows
		WHERE enabled = TRUE
		  AND start_time <= NOW()
		  AND end_time >= NOW()`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListActive returns currently active maintenance windows.
func (s *MaintenanceWindowStore) ListActive(ctx context.Context) ([]*MaintenanceWindow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''),
		       start_time, end_time,
		       recurring, COALESCE(recurrence_pattern,''),
		       suppress_alerts, suppress_notifications,
		       COALESCE(affected_agents,'{}'), COALESCE(affected_groups,'{}'),
		       enabled, created_by::text,
		       created_at, updated_at
		FROM maintenance_windows
		WHERE enabled = TRUE
		  AND start_time <= NOW()
		  AND end_time >= NOW()
		ORDER BY start_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []*MaintenanceWindow
	for rows.Next() {
		w := &MaintenanceWindow{}
		var createdBy *string
		if err := rows.Scan(
			&w.ID, &w.Name, &w.Description,
			&w.StartTime, &w.EndTime,
			&w.Recurring, &w.RecurrencePattern,
			&w.SuppressAlerts, &w.SuppressNotifications,
			&w.AffectedAgents, &w.AffectedGroups,
			&w.Enabled, &createdBy,
			&w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			continue
		}
		w.CreatedBy = createdBy
		if w.AffectedAgents == nil {
			w.AffectedAgents = []string{}
		}
		if w.AffectedGroups == nil {
			w.AffectedGroups = []string{}
		}
		windows = append(windows, w)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if windows == nil {
		windows = []*MaintenanceWindow{}
	}
	return windows, nil
}
