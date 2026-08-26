package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"
)

// NotificationPrefs holds a user's email notification preferences.
type NotificationPrefs struct {
	ID                 string    `json:"id"`
	UserID             string    `json:"user_id"`
	EmailEnabled       bool      `json:"email_enabled"`
	EmailAddress       string    `json:"email_address"`
	MinSeverity        string    `json:"min_severity"`
	NotifyIncidents    bool      `json:"notify_incidents"`
	NotifyAgentOffline bool      `json:"notify_agent_offline"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// NotificationPrefStore provides access to notification_preferences.
type NotificationPrefStore struct {
	db *DB
}

// NewNotificationPrefStore creates a NotificationPrefStore.
func NewNotificationPrefStore(db *DB) *NotificationPrefStore {
	return &NotificationPrefStore{db: db}
}

// GetByUserID returns the preferences for userID.
// If no row exists, a default struct is returned (not an error).
// defaultNotificationPrefs は、まだ設定していない利用者に返す既定です。
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。** 検査
// ファイルには、この構造体をそのまま書き写したものが置いてありました。
//
// `MinSeverity` は `critical` です —— **既定が緩いと、設定していない
// 利用者に通知が溢れます。厳しいと、届くはずのものが届きません。**
// どちらも「設定を変えたつもりが効いていない」と見分けが付きません。
func defaultNotificationPrefs(userID string) *NotificationPrefs {
	return &NotificationPrefs{
		UserID:      userID,
		MinSeverity: "critical",
	}
}

func (s *NotificationPrefStore) GetByUserID(ctx context.Context, userID string) (*NotificationPrefs, error) {
	p := defaultNotificationPrefs(userID)
	err := s.db.Pool().QueryRow(ctx, `
		SELECT id::text, email_enabled, COALESCE(email_address,''),
		       min_severity, notify_incidents, notify_agent_offline,
		       created_at, updated_at
		FROM notification_preferences
		WHERE user_id = $1`, userID).
		Scan(&p.ID, &p.EmailEnabled, &p.EmailAddress,
			&p.MinSeverity, &p.NotifyIncidents, &p.NotifyAgentOffline,
			&p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// まだ設定していない。既定値で返します。
		p.ID = ""
		return p, nil
	}
	if err != nil {
		// 以前はどんな失敗も「まだ設定していない」でした。既定は
		// MinSeverity: critical なので、利用者が high まで通知するように
		// していても、読めなかっただけで critical だけになります。
		return nil, fmt.Errorf("通知設定を読めませんでした: %w", err)
	}
	return p, nil
}

// Upsert inserts or updates notification preferences for a user.
func (s *NotificationPrefStore) Upsert(ctx context.Context, p *NotificationPrefs) (*NotificationPrefs, error) {
	var id string
	err := s.db.Pool().QueryRow(ctx, `
		INSERT INTO notification_preferences
			(user_id, email_enabled, email_address, min_severity,
			 notify_incidents, notify_agent_offline, updated_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			email_enabled       = EXCLUDED.email_enabled,
			email_address       = EXCLUDED.email_address,
			min_severity        = EXCLUDED.min_severity,
			notify_incidents    = EXCLUDED.notify_incidents,
			notify_agent_offline = EXCLUDED.notify_agent_offline,
			updated_at          = NOW()
		RETURNING id::text`,
		p.UserID, p.EmailEnabled, p.EmailAddress, p.MinSeverity,
		p.NotifyIncidents, p.NotifyAgentOffline,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	p.ID = id
	return s.GetByUserID(ctx, p.UserID)
}

// ListEmailEnabled returns all prefs with email_enabled=true and
// min_severity at or above the given severity level.
// severityOrder: critical=4, high=3, medium=2, low=1
func (s *NotificationPrefStore) ListEmailEnabled(ctx context.Context, severity string) ([]*NotificationPrefs, error) {
	// Build a severity threshold: rows where the event severity is >= min_severity.
	// We map severity text to an integer for comparison.
	rows, err := s.db.Pool().Query(ctx, `
		SELECT id::text, user_id::text, email_enabled,
		       COALESCE(email_address,''), min_severity,
		       notify_incidents, notify_agent_offline,
		       created_at, updated_at
		FROM notification_preferences
		WHERE email_enabled = true
		  AND email_address IS NOT NULL
		  AND email_address <> ''
		  AND CASE min_severity
		        WHEN 'low'      THEN 1
		        WHEN 'medium'   THEN 2
		        WHEN 'high'     THEN 3
		        WHEN 'critical' THEN 4
		        ELSE 4
		      END <= CASE $1
		        WHEN 'low'      THEN 1
		        WHEN 'medium'   THEN 2
		        WHEN 'high'     THEN 3
		        WHEN 'critical' THEN 4
		        ELSE 0
		      END`, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*NotificationPrefs
	for rows.Next() {
		p := &NotificationPrefs{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.EmailEnabled, &p.EmailAddress,
			&p.MinSeverity, &p.NotifyIncidents, &p.NotifyAgentOffline,
			&p.CreatedAt, &p.UpdatedAt); err == nil {
			result = append(result, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		result = []*NotificationPrefs{}
	}
	return result, nil
}
