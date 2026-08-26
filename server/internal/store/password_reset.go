package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidResetToken は無効または期限切れのリセットトークンを示す。
var ErrInvalidResetToken = errors.New("パスワードリセットトークンが無効または期限切れです")

// PasswordResetStore はパスワードリセットトークンのデータベース操作を担当する。
type PasswordResetStore struct {
	pool *pgxpool.Pool
}

// NewPasswordResetStore は PasswordResetStore を作成する。
func NewPasswordResetStore(db *DB) *PasswordResetStore {
	return &PasswordResetStore{pool: db.Pool()}
}

// Create は32バイトのcrypto/randトークンを生成し、bcryptハッシュでDBに保存する。
// 生のトークン(64文字の16進数文字列)を返す。
func (s *PasswordResetStore) Create(ctx context.Context, userID string) (string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", fmt.Errorf("トークン生成に失敗しました: %w", err)
	}
	rawToken := hex.EncodeToString(rawBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("トークンのハッシュ化に失敗しました: %w", err)
	}

	// 既存の未使用トークンを無効化
	_, err = s.pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used = TRUE
		 WHERE user_id = $1::uuid AND NOT used`,
		userID,
	)
	if err != nil {
		return "", fmt.Errorf("既存トークンの無効化に失敗しました: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO password_reset_tokens (user_id, token_hash)
		 VALUES ($1::uuid, $2)`,
		userID, string(hash),
	)
	if err != nil {
		return "", fmt.Errorf("トークンの保存に失敗しました: %w", err)
	}

	return rawToken, nil
}

// Verify は生トークンを検証し、有効な場合はユーザーIDを返す。
// 期限切れ・使用済みの場合は ErrInvalidResetToken を返す。
func (s *PasswordResetStore) Verify(ctx context.Context, rawToken string) (string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id::text, token_hash FROM password_reset_tokens
		 WHERE NOT used AND expires_at > NOW()
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return "", fmt.Errorf("トークン検索に失敗しました: %w", err)
	}
	defer rows.Close()

	type row struct {
		id     string
		userID string
		hash   string
	}
	var candidates []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.userID, &r.hash); err != nil {
			continue
		}
		candidates = append(candidates, r)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return "", err
	}
	rows.Close()

	if len(candidates) == 0 {
		return "", ErrInvalidResetToken
	}

	for _, r := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(r.hash), []byte(rawToken)) == nil {
			return r.userID, nil
		}
	}

	return "", ErrInvalidResetToken
}

// MarkUsed はトークンを使用済みにする。
func (s *PasswordResetStore) MarkUsed(ctx context.Context, rawToken string) error {
	rows, err := s.pool.Query(ctx,
		`SELECT id, token_hash FROM password_reset_tokens
		 WHERE NOT used AND expires_at > NOW()`,
	)
	if err != nil {
		return fmt.Errorf("トークン検索に失敗しました: %w", err)
	}
	defer rows.Close()

	type row struct {
		id   string
		hash string
	}
	var candidates []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			continue
		}
		candidates = append(candidates, r)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, r := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(r.hash), []byte(rawToken)) == nil {
			_, err = s.pool.Exec(ctx,
				"UPDATE password_reset_tokens SET used = TRUE WHERE id = $1",
				r.id,
			)
			return err
		}
	}
	return nil
}

// CleanupExpired は期限切れのトークンを削除する。
func (s *PasswordResetStore) CleanupExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = TRUE",
	)
	return err
}
