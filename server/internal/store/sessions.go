package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Session represents an active JWT session stored in the database.
type Session struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	JTI        string                 `json:"jti"`
	DeviceInfo map[string]interface{} `json:"device_info"`
	IPAddress  string                 `json:"ip_address"`
	CreatedAt  time.Time              `json:"created_at"`
	LastSeenAt time.Time              `json:"last_seen_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
	Revoked    bool                   `json:"revoked"`
}

// SessionStore handles user session database operations.
type SessionStore struct {
	pool *pgxpool.Pool
}

// NewSessionStore creates a new SessionStore.
func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{pool: pool}
}

// Create records a new session in the database (called at login time).
func (s *SessionStore) Create(ctx context.Context, sess Session) error {
	deviceInfoJSON, err := json.Marshal(sess.DeviceInfo)
	if err != nil {
		return fmt.Errorf("device_info のシリアライズに失敗しました: %w", err)
	}

	ipAddr := sess.IPAddress
	if ipAddr == "" {
		ipAddr = "0.0.0.0"
	}

	userAgent := ""
	if ua, ok := sess.DeviceInfo["user_agent"].(string); ok {
		userAgent = ua
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_sessions (user_id, jti, device_info, ip_address, user_agent, created_at, last_seen_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, false)`,
		sess.UserID,
		sess.JTI,
		deviceInfoJSON,
		ipAddr,
		userAgent,
		sess.CreatedAt,
		sess.LastSeenAt,
		sess.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("セッションの作成に失敗しました: %w", err)
	}
	return nil
}

// ListByUser returns all active (non-revoked, non-expired) sessions for the given user.
func (s *SessionStore) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, jti, device_info, COALESCE(ip_address::text, ''), created_at, last_seen_at, expires_at, revoked
		FROM user_sessions
		WHERE user_id = $1
		  AND NOT revoked
		  AND expires_at > NOW()
		ORDER BY last_seen_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("セッション一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var sess Session
		var deviceInfoRaw []byte
		if err := rows.Scan(
			&sess.ID,
			&sess.UserID,
			&sess.JTI,
			&deviceInfoRaw,
			&sess.IPAddress,
			&sess.CreatedAt,
			&sess.LastSeenAt,
			&sess.ExpiresAt,
			&sess.Revoked,
		); err != nil {
			return nil, fmt.Errorf("セッション行のスキャンに失敗しました: %w", err)
		}
		if len(deviceInfoRaw) > 0 {
			if err := json.Unmarshal(deviceInfoRaw, &sess.DeviceInfo); err != nil {
				sess.DeviceInfo = map[string]interface{}{}
			}
		} else {
			sess.DeviceInfo = map[string]interface{}{}
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("セッション行の読み取りに失敗しました: %w", err)
	}

	if sessions == nil {
		sessions = []Session{}
	}
	return sessions, nil
}

// UpdateLastSeen updates the last_seen_at timestamp for the session identified by JTI.
func (s *SessionStore) UpdateLastSeen(ctx context.Context, jti string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE user_sessions
		SET last_seen_at = NOW()
		WHERE jti = $1 AND NOT revoked`,
		jti,
	)
	if err != nil {
		return fmt.Errorf("last_seen_at の更新に失敗しました: %w", err)
	}
	return nil
}

// Revoke marks a specific session as revoked.
// Only the session owner (matched by userID) can revoke their own session.
func (s *SessionStore) Revoke(ctx context.Context, sessionID, userID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE user_sessions
		SET revoked = true
		WHERE id = $1 AND user_id = $2`,
		sessionID,
		userID,
	)
	if err != nil {
		return fmt.Errorf("セッションの失効に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("セッションが見つからないか、アクセス権がありません")
	}
	return nil
}

// RevokeByID revokes a session by ID without checking ownership (admin use).
func (s *SessionStore) RevokeByID(ctx context.Context, sessionID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE user_sessions
		SET revoked = true
		WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("セッションの失効に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("セッションが見つかりません")
	}
	return nil
}

// GetJTIByID returns the JTI and ExpiresAt for a session by its ID.
// Used to add the JTI to the in-memory blocklist when revoking.
func (s *SessionStore) GetJTIByID(ctx context.Context, sessionID string) (jti string, expiresAt time.Time, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT jti, expires_at
		FROM user_sessions
		WHERE id = $1`,
		sessionID,
	).Scan(&jti, &expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("セッション情報の取得に失敗しました: %w", err)
	}
	return jti, expiresAt, nil
}

// RevokeAll marks all sessions for the given user as revoked (e.g. on password change).
// Returns the list of (jti, expiresAt) pairs for blocklist registration.
func (s *SessionStore) RevokeAll(ctx context.Context, userID string) ([]struct {
	JTI       string
	ExpiresAt time.Time
}, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE user_sessions
		SET revoked = true
		WHERE user_id = $1 AND NOT revoked
		RETURNING jti, expires_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("全セッションの失効に失敗しました: %w", err)
	}
	defer rows.Close()

	var revoked []struct {
		JTI       string
		ExpiresAt time.Time
	}
	for rows.Next() {
		var entry struct {
			JTI       string
			ExpiresAt time.Time
		}
		if err := rows.Scan(&entry.JTI, &entry.ExpiresAt); err != nil {
			return nil, fmt.Errorf("失効セッション行のスキャンに失敗しました: %w", err)
		}
		revoked = append(revoked, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("失効セッション行の読み取りに失敗しました: %w", err)
	}
	return revoked, nil
}

// RevokeAllExcept marks all sessions for the given user as revoked, except the specified JTI.
// Returns the list of (jti, expiresAt) pairs for blocklist registration.
func (s *SessionStore) RevokeAllExcept(ctx context.Context, userID, exceptJTI string) ([]struct {
	JTI       string
	ExpiresAt time.Time
}, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE user_sessions
		SET revoked = true
		WHERE user_id = $1 AND jti != $2 AND NOT revoked
		RETURNING jti, expires_at`,
		userID,
		exceptJTI,
	)
	if err != nil {
		return nil, fmt.Errorf("他セッションの失効に失敗しました: %w", err)
	}
	defer rows.Close()

	var revoked []struct {
		JTI       string
		ExpiresAt time.Time
	}
	for rows.Next() {
		var entry struct {
			JTI       string
			ExpiresAt time.Time
		}
		if err := rows.Scan(&entry.JTI, &entry.ExpiresAt); err != nil {
			return nil, fmt.Errorf("失効セッション行のスキャンに失敗しました: %w", err)
		}
		revoked = append(revoked, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("失効セッション行の読み取りに失敗しました: %w", err)
	}
	return revoked, nil
}

// CleanupExpired removes expired session records from the database.
// Intended to be called periodically (e.g., daily cron).
func (s *SessionStore) CleanupExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM user_sessions
		WHERE expires_at < NOW()`)
	if err != nil {
		return fmt.Errorf("期限切れセッションの削除に失敗しました: %w", err)
	}
	return nil
}
