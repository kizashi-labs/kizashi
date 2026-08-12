package store

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PushTokenStore struct{ db *pgxpool.Pool }

func NewPushTokenStore(db *pgxpool.Pool) *PushTokenStore {
	return &PushTokenStore{db: db}
}

type PushToken struct {
	ID       string
	UserID   string
	Token    string
	Platform string // "ios" | "android"
}

func (s *PushTokenStore) Upsert(ctx context.Context, userID, token, platform string) error {
	_, err := s.db.Exec(ctx, `
        INSERT INTO mobile_push_tokens (user_id, token, platform, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_id, platform)
        DO UPDATE SET token = EXCLUDED.token, updated_at = NOW()
    `, userID, token, platform)
	return err
}

func (s *PushTokenStore) GetByUserID(ctx context.Context, userID string) ([]PushToken, error) {
	rows, err := s.db.Query(ctx, `
        SELECT id, user_id, token, platform FROM mobile_push_tokens WHERE user_id = $1
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []PushToken
	for rows.Next() {
		var t PushToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Token, &t.Platform); err != nil {
			continue
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *PushTokenStore) GetAllTokens(ctx context.Context) ([]PushToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, token, platform FROM mobile_push_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []PushToken
	for rows.Next() {
		var t PushToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Token, &t.Platform); err != nil {
			continue
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}
