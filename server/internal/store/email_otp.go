package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ErrExpired は期限切れまたは使用済みのOTPコードを示す。
var ErrExpired = errors.New("OTPコードが期限切れまたは使用済みです")

// EmailOTPStore はメールOTPコードのデータベース操作を担当する。
type EmailOTPStore struct {
	pool *pgxpool.Pool
}

// NewEmailOTPStore は EmailOTPStore を作成する。
func NewEmailOTPStore(db *DB) *EmailOTPStore {
	return &EmailOTPStore{pool: db.Pool()}
}

// Generate は6桁OTPを生成しbcryptハッシュで保存する。
// 平文コード(000000–999999)を文字列で返す。
func (s *EmailOTPStore) Generate(ctx context.Context, userID, purpose string) (string, error) {
	// crypto/rand で 0–999999 の乱数を生成
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("OTP乱数生成に失敗しました: %w", err)
	}
	plain := fmt.Sprintf("%06d", n.Int64())

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), 10)
	if err != nil {
		return "", fmt.Errorf("OTPハッシュ化に失敗しました: %w", err)
	}

	// 同ユーザー・同purposeの未使用コードを事前に無効化（used=trueに）
	_, err = s.pool.Exec(ctx,
		`UPDATE email_otp_codes
		 SET used = TRUE
		 WHERE user_id = $1::uuid AND purpose = $2 AND NOT used`,
		userID, purpose,
	)
	if err != nil {
		return "", fmt.Errorf("既存OTPの無効化に失敗しました: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO email_otp_codes (user_id, code, purpose)
		 VALUES ($1::uuid, $2, $3)`,
		userID, string(hash), purpose,
	)
	if err != nil {
		return "", fmt.Errorf("OTPの保存に失敗しました: %w", err)
	}

	return plain, nil
}

// Verify はコードを検証し消費する (used=true にする)。
// 期限切れ・使用済みの場合は ErrExpired を返す。
func (s *EmailOTPStore) Verify(ctx context.Context, userID, code, purpose string) error {
	rows, err := s.pool.Query(ctx,
		`SELECT id, code FROM email_otp_codes
		 WHERE user_id = $1::uuid
		   AND purpose = $2
		   AND NOT used
		   AND expires_at > NOW()
		 ORDER BY created_at DESC`,
		userID, purpose,
	)
	if err != nil {
		return fmt.Errorf("OTP検索に失敗しました: %w", err)
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
	rows.Close()

	if len(candidates) == 0 {
		return ErrExpired
	}

	for _, r := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(r.hash), []byte(code)) == nil {
			// コードを消費
			_, err = s.pool.Exec(ctx,
				"UPDATE email_otp_codes SET used = TRUE WHERE id = $1",
				r.id,
			)
			if err != nil {
				return fmt.Errorf("OTP消費に失敗しました: %w", err)
			}
			return nil
		}
	}

	return ErrExpired
}

// Cleanup は期限切れコードを削除する。
func (s *EmailOTPStore) Cleanup(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM email_otp_codes WHERE expires_at < NOW() OR used = TRUE",
	)
	return err
}
