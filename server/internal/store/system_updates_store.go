package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemUpdate represents a single available/applied platform update.
//
// Phase 1: rows are inserted manually (or via test fixtures); Phase 2 will add
// a GitHub Releases poller that inserts on detection. Status transitions are
// gated by the API handler — the store only writes whatever it is given.
type SystemUpdate struct {
	ID                  string     `json:"id"`
	CurrentVersion      string     `json:"current_version"`
	AvailableVersion    string     `json:"available_version"`
	ReleaseNotesURL     string     `json:"release_notes_url"`
	ReleaseNotesMD      string     `json:"release_notes_md"`
	Channel             string     `json:"channel"`
	DetectedAt          time.Time  `json:"detected_at"`
	Status              string     `json:"status"`
	ApprovedBy          *string    `json:"approved_by,omitempty"`
	ApprovedAt          *time.Time `json:"approved_at,omitempty"`
	AppliedAt           *time.Time `json:"applied_at,omitempty"`
	FailedReason        string     `json:"failed_reason"`
	RollbackFromVersion string     `json:"rollback_from_version"`
}

// SystemUpdateSettings is the single-row policy table.
type SystemUpdateSettings struct {
	AutoApplyPatch         bool      `json:"auto_apply_patch"`
	AutoApplyMinor         bool      `json:"auto_apply_minor"`
	MaintenanceWindowStart *string   `json:"maintenance_window_start,omitempty"` // "HH:MM"
	MaintenanceWindowEnd   *string   `json:"maintenance_window_end,omitempty"`   // "HH:MM"
	NotifyEmail            string    `json:"notify_email"`
	Channel                string    `json:"channel"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// CreateSystemUpdateInput is the input for inserting a newly-detected update.
type CreateSystemUpdateInput struct {
	CurrentVersion   string `json:"current_version"   binding:"required"`
	AvailableVersion string `json:"available_version" binding:"required"`
	ReleaseNotesURL  string `json:"release_notes_url"`
	ReleaseNotesMD   string `json:"release_notes_md"`
	Channel          string `json:"channel"`
}

// UpdateSettingsInput is the input for replacing settings.
type UpdateSettingsInput struct {
	AutoApplyPatch         bool    `json:"auto_apply_patch"`
	AutoApplyMinor         bool    `json:"auto_apply_minor"`
	MaintenanceWindowStart *string `json:"maintenance_window_start,omitempty"`
	MaintenanceWindowEnd   *string `json:"maintenance_window_end,omitempty"`
	NotifyEmail            string  `json:"notify_email"`
	Channel                string  `json:"channel" binding:"required"`
}

// SystemUpdatesStore handles CRUD for the system_updates and
// system_update_settings tables.
type SystemUpdatesStore struct {
	pool *pgxpool.Pool
}

// NewSystemUpdatesStore creates a new SystemUpdatesStore.
func NewSystemUpdatesStore(pool *pgxpool.Pool) *SystemUpdatesStore {
	return &SystemUpdatesStore{pool: pool}
}

// List returns all updates, newest detected_at first.
func (s *SystemUpdatesStore) List(ctx context.Context) ([]SystemUpdate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, current_version, available_version, release_notes_url, release_notes_md,
		       channel, detected_at, status, approved_by, approved_at, applied_at,
		       failed_reason, rollback_from_version
		FROM system_updates
		ORDER BY detected_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := []SystemUpdate{}
	for rows.Next() {
		u, err := scanSystemUpdate(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// Get returns a single update by ID.
func (s *SystemUpdatesStore) Get(ctx context.Context, id string) (SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, current_version, available_version, release_notes_url, release_notes_md,
		       channel, detected_at, status, approved_by, approved_at, applied_at,
		       failed_reason, rollback_from_version
		FROM system_updates WHERE id = $1
	`, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("system update not found: %w", err)
	}
	return u, nil
}

// NextApproved returns the oldest 'approved' row (FIFO by approved_at)
// for the updater's DBPoller to apply next. Returns (nil, nil) when no
// approved rows exist. Picking the oldest first means a queue of
// approvals is processed in the order admins approved them.
func (s *SystemUpdatesStore) NextApproved(ctx context.Context) (*SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, current_version, available_version, release_notes_url, release_notes_md,
		       channel, detected_at, status, approved_by, approved_at, applied_at,
		       failed_reason, rollback_from_version
		FROM system_updates
		WHERE status = 'approved'
		ORDER BY approved_at ASC NULLS LAST
		LIMIT 1
	`)
	u, err := scanSystemUpdate(row)
	if err != nil {
		// No row is the common case; treat as (nil, nil) so callers can
		// loop without distinguishing ErrNoRows from other errors.
		return nil, nil
	}
	return &u, nil
}

// LatestAvailable returns the newest update whose status is 'available' or
// 'approved' (i.e. not yet successfully applied or otherwise terminal).
// Returns (nil, nil) when no candidate exists.
func (s *SystemUpdatesStore) LatestAvailable(ctx context.Context) (*SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, current_version, available_version, release_notes_url, release_notes_md,
		       channel, detected_at, status, approved_by, approved_at, applied_at,
		       failed_reason, rollback_from_version
		FROM system_updates
		WHERE status IN ('available', 'approved', 'applying')
		ORDER BY detected_at DESC
		LIMIT 1
	`)
	u, err := scanSystemUpdate(row)
	if err != nil {
		// No row is not an error here — caller treats nil as "no update".
		return nil, nil
	}
	return &u, nil
}

// Create inserts a newly-detected update. Returns the inserted row.
// Returns an error if available_version already exists (UNIQUE constraint).
func (s *SystemUpdatesStore) Create(ctx context.Context, in CreateSystemUpdateInput) (SystemUpdate, error) {
	channel := in.Channel
	if channel == "" {
		channel = "stable"
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO system_updates (current_version, available_version, release_notes_url, release_notes_md, channel)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, in.CurrentVersion, in.AvailableVersion, in.ReleaseNotesURL, in.ReleaseNotesMD, channel)
	return scanSystemUpdate(row)
}

// Approve transitions an update from 'available' to 'approved'.
// Returns the updated row, or an error if the current status is not 'available'.
func (s *SystemUpdatesStore) Approve(ctx context.Context, id, approvedBy string) (SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'approved', approved_by = $1, approved_at = NOW()
		WHERE id = $2 AND status = 'available'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, approvedBy, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'available' state or not found: %w", err)
	}
	return u, nil
}

// Cancel transitions an update from 'approved' back to 'available'.
// Returns an error if the current status is not 'approved'.
func (s *SystemUpdatesStore) Cancel(ctx context.Context, id string) (SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'available', approved_by = NULL, approved_at = NULL
		WHERE id = $1 AND status = 'approved'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'approved' state or not found: %w", err)
	}
	return u, nil
}

// MarkApplying transitions 'approved' → 'applying' and records the version
// to roll back to on failure. Used by the updater container's Applier when
// it picks up an approved row.
func (s *SystemUpdatesStore) MarkApplying(ctx context.Context, id, rollbackFromVersion string) (SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'applying', rollback_from_version = $1
		WHERE id = $2 AND status = 'approved'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, rollbackFromVersion, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'approved' state or not found: %w", err)
	}
	return u, nil
}

// MarkSuccess transitions 'applying' → 'success' and stamps applied_at.
func (s *SystemUpdatesStore) MarkSuccess(ctx context.Context, id string) (SystemUpdate, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'success', applied_at = NOW(), failed_reason = ''
		WHERE id = $1 AND status = 'applying'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'applying' state or not found: %w", err)
	}
	return u, nil
}

// MarkFailed transitions 'applying' → 'failed' with a reason. Long reasons
// are truncated at 1000 chars to keep the row size bounded.
func (s *SystemUpdatesStore) MarkFailed(ctx context.Context, id, reason string) (SystemUpdate, error) {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'failed', failed_reason = $1
		WHERE id = $2 AND status = 'applying'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, reason, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'applying' state or not found: %w", err)
	}
	return u, nil
}

// MarkRolledBack transitions 'applying' → 'rolled_back' after the Applier
// has reverted IMAGE_TAG to rollback_from_version and verified the rollback
// is healthy. Reason describes why the original apply failed (e.g. "health
// check timeout after compose up").
func (s *SystemUpdatesStore) MarkRolledBack(ctx context.Context, id, reason string) (SystemUpdate, error) {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE system_updates
		SET status = 'rolled_back', failed_reason = $1
		WHERE id = $2 AND status = 'applying'
		RETURNING id, current_version, available_version, release_notes_url, release_notes_md,
		          channel, detected_at, status, approved_by, approved_at, applied_at,
		          failed_reason, rollback_from_version
	`, reason, id)
	u, err := scanSystemUpdate(row)
	if err != nil {
		return SystemUpdate{}, fmt.Errorf("update not in 'applying' state or not found: %w", err)
	}
	return u, nil
}

// GetSettings returns the single settings row. The migration ensures id=1
// always exists, so this should never return ErrNoRows in practice.
func (s *SystemUpdatesStore) GetSettings(ctx context.Context) (SystemUpdateSettings, error) {
	var st SystemUpdateSettings
	var startStr, endStr *string
	err := s.pool.QueryRow(ctx, `
		SELECT auto_apply_patch, auto_apply_minor,
		       to_char(maintenance_window_start, 'HH24:MI'),
		       to_char(maintenance_window_end,   'HH24:MI'),
		       notify_email, channel, updated_at
		FROM system_update_settings WHERE id = 1
	`).Scan(&st.AutoApplyPatch, &st.AutoApplyMinor, &startStr, &endStr,
		&st.NotifyEmail, &st.Channel, &st.UpdatedAt)
	if err != nil {
		return st, err
	}
	st.MaintenanceWindowStart = startStr
	st.MaintenanceWindowEnd = endStr
	return st, nil
}

// UpdateSettings replaces all settings fields. Validation (channel value,
// email format, window-start/end pairing) is the caller's responsibility.
func (s *SystemUpdatesStore) UpdateSettings(ctx context.Context, in UpdateSettingsInput) (SystemUpdateSettings, error) {
	_, err := s.pool.Exec(ctx, `
		UPDATE system_update_settings
		SET auto_apply_patch         = $1,
		    auto_apply_minor         = $2,
		    maintenance_window_start = $3::time,
		    maintenance_window_end   = $4::time,
		    notify_email             = $5,
		    channel                  = $6,
		    updated_at               = NOW()
		WHERE id = 1
	`, in.AutoApplyPatch, in.AutoApplyMinor,
		nullableTime(in.MaintenanceWindowStart),
		nullableTime(in.MaintenanceWindowEnd),
		in.NotifyEmail, in.Channel)
	if err != nil {
		return SystemUpdateSettings{}, err
	}
	return s.GetSettings(ctx)
}

// nullableTime returns nil for empty/nil input, otherwise the dereferenced string.
// Used to translate "" → SQL NULL for TIME columns.
func nullableTime(s *string) interface{} {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

// scanner is the minimal interface shared by *pgx.Rows and pgx.Row Scan results.
type scanner interface {
	Scan(dest ...any) error
}

func scanSystemUpdate(s scanner) (SystemUpdate, error) {
	var u SystemUpdate
	err := s.Scan(
		&u.ID, &u.CurrentVersion, &u.AvailableVersion, &u.ReleaseNotesURL, &u.ReleaseNotesMD,
		&u.Channel, &u.DetectedAt, &u.Status, &u.ApprovedBy, &u.ApprovedAt, &u.AppliedAt,
		&u.FailedReason, &u.RollbackFromVersion,
	)
	return u, err
}
