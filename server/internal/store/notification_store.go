package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertNotifChannel represents a notification channel for alert dispatching.
type AlertNotifChannel struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"` // webhook_slack, webhook_teams, webhook_generic, email
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// CreateAlertNotifChannelInput is the input for creating or updating an alert notification channel.
type CreateAlertNotifChannelInput struct {
	Name    string          `json:"name" binding:"required"`
	Type    string          `json:"type" binding:"required"`
	Config  json.RawMessage `json:"config"`
	Enabled bool            `json:"enabled"`
}

// AlertNotifStore handles CRUD for the notification_channels table.
type AlertNotifStore struct {
	pool *pgxpool.Pool
}

// NewAlertNotifStore creates a new AlertNotifStore.
func NewAlertNotifStore(pool *pgxpool.Pool) *AlertNotifStore {
	return &AlertNotifStore{pool: pool}
}

// List returns all notification channels ordered by creation time.
func (s *AlertNotifStore) List(ctx context.Context) ([]AlertNotifChannel, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, type, config, enabled, created_at, updated_at FROM notification_channels ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []AlertNotifChannel
	for rows.Next() {
		var c AlertNotifChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, c)
	}
	if results == nil {
		results = []AlertNotifChannel{}
	}
	return results, nil
}

// Create inserts a new notification channel and returns the created record.
func (s *AlertNotifStore) Create(ctx context.Context, in CreateAlertNotifChannelInput) (AlertNotifChannel, error) {
	var c AlertNotifChannel
	err := s.pool.QueryRow(ctx,
		`INSERT INTO notification_channels (name, type, config, enabled) VALUES ($1, $2, $3, $4)
         RETURNING id, name, type, config, enabled, created_at, updated_at`,
		in.Name, in.Type, in.Config, in.Enabled,
	).Scan(&c.ID, &c.Name, &c.Type, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// Update modifies an existing notification channel by ID.
func (s *AlertNotifStore) Update(ctx context.Context, id string, in CreateAlertNotifChannelInput) (AlertNotifChannel, error) {
	var c AlertNotifChannel
	err := s.pool.QueryRow(ctx,
		`UPDATE notification_channels SET name=$1, type=$2, config=$3, enabled=$4, updated_at=NOW()
         WHERE id=$5 RETURNING id, name, type, config, enabled, created_at, updated_at`,
		in.Name, in.Type, in.Config, in.Enabled, id,
	).Scan(&c.ID, &c.Name, &c.Type, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, fmt.Errorf("notification channel not found: %w", err)
	}
	return c, nil
}

// Delete removes a notification channel by ID.
func (s *AlertNotifStore) Delete(ctx context.Context, id string) error {
	res, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("notification channel not found")
	}
	return nil
}

// Get returns a single notification channel by ID.
func (s *AlertNotifStore) Get(ctx context.Context, id string) (AlertNotifChannel, error) {
	var c AlertNotifChannel
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, type, config, enabled, created_at, updated_at FROM notification_channels WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.Type, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, fmt.Errorf("notification channel not found: %w", err)
	}
	return c, nil
}

// ListEnabled returns all enabled notification channels.
func (s *AlertNotifStore) ListEnabled(ctx context.Context) ([]AlertNotifChannel, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, type, config, enabled, created_at, updated_at FROM notification_channels WHERE enabled=true ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []AlertNotifChannel
	for rows.Next() {
		var c AlertNotifChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, c)
	}
	if results == nil {
		results = []AlertNotifChannel{}
	}
	return results, nil
}
