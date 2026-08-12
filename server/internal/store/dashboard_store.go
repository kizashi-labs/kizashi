package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DashboardLayout struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Widgets   json.RawMessage `json:"widgets"` // [{id, type, position, size, config}]
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type DashboardStore struct {
	pool *pgxpool.Pool
}

func NewDashboardStore(pool *pgxpool.Pool) *DashboardStore {
	return &DashboardStore{pool: pool}
}

func (s *DashboardStore) Get(ctx context.Context, userID string) (DashboardLayout, error) {
	var d DashboardLayout
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, widgets, created_at, updated_at FROM dashboard_layouts WHERE user_id=$1`,
		userID,
	).Scan(&d.ID, &d.UserID, &d.Widgets, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return d, fmt.Errorf("dashboard layout not found: %w", err)
	}
	return d, nil
}

func (s *DashboardStore) Upsert(ctx context.Context, userID string, widgets json.RawMessage) (DashboardLayout, error) {
	var d DashboardLayout
	err := s.pool.QueryRow(ctx,
		`INSERT INTO dashboard_layouts (user_id, widgets)
		 VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE SET widgets=$2, updated_at=NOW()
		 RETURNING id, user_id, widgets, created_at, updated_at`,
		userID, widgets,
	).Scan(&d.ID, &d.UserID, &d.Widgets, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}
