package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WidgetPref holds the visibility and display order for a single dashboard widget.
type WidgetPref struct {
	ID      string `json:"id"`
	Visible bool   `json:"visible"`
	Order   int    `json:"order"`
}

// DashboardPrefs represents a user's saved dashboard widget configuration.
type DashboardPrefs struct {
	UserID  string       `json:"user_id"`
	Widgets []WidgetPref `json:"widgets"`
}

// DashboardPrefsStore handles dashboard preference persistence.
type DashboardPrefsStore struct {
	pool *pgxpool.Pool
}

// NewDashboardPrefsStore creates a new DashboardPrefsStore.
func NewDashboardPrefsStore(pool *pgxpool.Pool) *DashboardPrefsStore {
	return &DashboardPrefsStore{pool: pool}
}

// Get retrieves the dashboard preferences for the given user.
// Returns nil, nil if no preferences have been saved yet.
func (s *DashboardPrefsStore) Get(ctx context.Context, userID string) (*DashboardPrefs, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT widgets
		FROM dashboard_preferences
		WHERE user_id = $1`,
		userID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ダッシュボード設定の取得に失敗しました: %w", err)
	}

	var widgets []WidgetPref
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &widgets); err != nil {
			return nil, fmt.Errorf("ダッシュボード設定のパースに失敗しました: %w", err)
		}
	}
	if widgets == nil {
		widgets = []WidgetPref{}
	}

	return &DashboardPrefs{
		UserID:  userID,
		Widgets: widgets,
	}, nil
}

// Upsert inserts or updates the dashboard preferences for the user.
func (s *DashboardPrefsStore) Upsert(ctx context.Context, prefs DashboardPrefs) error {
	widgetsJSON, err := json.Marshal(prefs.Widgets)
	if err != nil {
		return fmt.Errorf("ウィジェット設定のシリアライズに失敗しました: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO dashboard_preferences (user_id, widgets, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id) DO UPDATE
		SET widgets = EXCLUDED.widgets,
		    updated_at = NOW()`,
		prefs.UserID,
		widgetsJSON,
	)
	if err != nil {
		return fmt.Errorf("ダッシュボード設定の保存に失敗しました: %w", err)
	}
	return nil
}
