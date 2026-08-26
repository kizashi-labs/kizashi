package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// APIKey represents a programmatic API key for a user.
type APIKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Revoked    bool       `json:"revoked"`
	CreatedAt  time.Time  `json:"created_at"`
	// TenantID is the tenant the key's owner belongs to.
	//
	// `api_keys` にテナントの列はありません。鍵は利用者に紐づき、利用者は
	// テナントに紐づくので、`users` から引きます。**鍵そのものに持たせて
	// いないのは意図ではなく、単に繋がっていなかっただけです** ——
	// 認証層は無条件に空文字を置いていました。
	//
	// 引けなかったとき（利用者の行が消えている等）は空のままにします。
	// **空を「全テナント」と読み替えないのが、この一連の直しの要点です。**
	TenantID string `json:"-"`
}

// APIKeyStore handles API key database operations.
type APIKeyStore struct {
	pool *pgxpool.Pool
}

// NewAPIKeyStore creates a new APIKeyStore.
func NewAPIKeyStore(pool *pgxpool.Pool) *APIKeyStore {
	return &APIKeyStore{pool: pool}
}

// hashKey computes the SHA-256 hex digest of the raw key.
func hashKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// Create generates a new API key for the given user and stores its hash.
// Returns the raw key (shown once) and any error.
func (s *APIKeyStore) Create(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (string, error) {
	// Generate 32 random bytes → 64-char hex suffix
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("乱数の生成に失敗しました: %w", err)
	}
	rawKey := "edr_" + hex.EncodeToString(b)
	keyPrefix := rawKey[:8] // "edr_" + 4 chars
	keyHash := hashKey(rawKey)

	if len(scopes) == 0 {
		scopes = []string{"read"}
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO api_keys (user_id, name, key_prefix, key_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID,
		name,
		keyPrefix,
		keyHash,
		scopes,
		expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("APIキーの作成に失敗しました: %w", err)
	}
	return rawKey, nil
}

// FindByKey looks up an API key by its raw value (hashed for lookup).
// Returns only non-revoked, non-expired keys.
func (s *APIKeyStore) FindByKey(ctx context.Context, rawKey string) (*APIKey, error) {
	keyHash := hashKey(rawKey)

	var k APIKey
	// 鍵の持ち主のテナントも一緒に引きます。LEFT JOIN なので、利用者の
	// 行が無ければ tenant は NULL のままで、鍵は「テナント不明」として
	// 扱われます（拒否される側に倒れます）。
	var tenant *string
	err := s.pool.QueryRow(ctx, `
		SELECT k.id, k.user_id, k.name, k.key_prefix, k.scopes,
		       k.last_used_at, k.expires_at, k.revoked, k.created_at,
		       u.tenant_id::text
		FROM api_keys k
		LEFT JOIN users u ON u.id = k.user_id
		WHERE k.key_hash = $1
		  AND NOT k.revoked
		  AND (k.expires_at IS NULL OR k.expires_at > NOW())`,
		keyHash,
	).Scan(
		&k.ID,
		&k.UserID,
		&k.Name,
		&k.KeyPrefix,
		&k.Scopes,
		&k.LastUsedAt,
		&k.ExpiresAt,
		&k.Revoked,
		&k.CreatedAt,
		&tenant,
	)
	if err != nil {
		return nil, fmt.Errorf("APIキーが見つかりません: %w", err)
	}
	if tenant != nil {
		k.TenantID = *tenant
	}
	return &k, nil
}

// ListByUser returns all API keys for the given user (non-revoked, ordered by created_at desc).
func (s *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, key_prefix, scopes, last_used_at, expires_at, revoked, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("APIキー一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID,
			&k.UserID,
			&k.Name,
			&k.KeyPrefix,
			&k.Scopes,
			&k.LastUsedAt,
			&k.ExpiresAt,
			&k.Revoked,
			&k.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("APIキー行のスキャンに失敗しました: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("APIキー行の読み取りに失敗しました: %w", err)
	}
	if keys == nil {
		keys = []APIKey{}
	}
	return keys, nil
}

// Revoke marks a specific API key as revoked. Only the key owner can revoke it.
func (s *APIKeyStore) Revoke(ctx context.Context, id, userID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys
		SET revoked = true
		WHERE id = $1 AND user_id = $2`,
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("APIキーの失効に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("APIキーが見つからないか、アクセス権がありません")
	}
	return nil
}

// UpdateLastUsed updates the last_used_at timestamp for the given key ID.
func (s *APIKeyStore) UpdateLastUsed(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE api_keys
		SET last_used_at = NOW()
		WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("last_used_at の更新に失敗しました: %w", err)
	}
	return nil
}
