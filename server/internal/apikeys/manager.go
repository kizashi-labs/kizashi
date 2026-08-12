// Package apikeys provides API key generation, validation, and lifecycle management.
package apikeys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ValidScopes lists all recognised API key scopes.
var ValidScopes = []string{
	"read:alerts",
	"write:alerts",
	"read:agents",
	"write:agents",
	"read:rules",
	"write:rules",
	"read:reports",
	"admin",
}

// APIKey represents a programmatic API key record (key_hash is never returned to callers).
type APIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"` // first 8 chars for display
	KeyHash   string     `json:"-"`          // bcrypt hash, never returned
	UserID    string     `json:"user_id"`
	Role      string     `json:"role"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
}

// Manager handles API key operations backed by the database.
type Manager struct {
	pool *pgxpool.Pool
}

// NewManager creates a new Manager.
func NewManager(pool *pgxpool.Pool) *Manager {
	return &Manager{pool: pool}
}

// Generate creates a new API key, stores a bcrypt hash, and returns the raw key once.
//
// The raw key is formatted as "edr_" + base64url(32 random bytes) and is the only
// time the full key is visible. Callers must present it to the user immediately.
//
// Returns (key record, rawKey, error).
func (m *Manager) Generate(
	ctx context.Context,
	name, userID, role string,
	scopes []string,
	expiresIn *time.Duration,
) (*APIKey, string, error) {
	// Generate 32 random bytes
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	rawKey := "edr_" + base64.RawURLEncoding.EncodeToString(raw) // ~47 chars after prefix

	// First 8 chars as the display prefix
	prefix := rawKey
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	// bcrypt hash of the full raw key
	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash key: %w", err)
	}

	if role == "" {
		role = "analyst"
	}
	if len(scopes) == 0 {
		scopes = []string{"read:alerts"}
	}

	var expiresAt *time.Time
	if expiresIn != nil {
		t := time.Now().Add(*expiresIn)
		expiresAt = &t
	}

	var k APIKey
	err = m.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_prefix, key_hash, user_id, role, scopes, expires_at, enabled)
		VALUES ($1, $2, $3, NULLIF($4,'')::uuid, $5, $6, $7, true)
		RETURNING id, name, key_prefix, key_hash,
		          COALESCE(user_id::text,''), role, scopes,
		          expires_at, last_used, enabled, created_at`,
		name, prefix, string(hash), userID, role, scopes, expiresAt,
	).Scan(
		&k.ID, &k.Name, &k.KeyPrefix, &k.KeyHash,
		&k.UserID, &k.Role, &k.Scopes,
		&k.ExpiresAt, &k.LastUsed, &k.Enabled, &k.CreatedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to store api key: %w", err)
	}

	return &k, rawKey, nil
}

// Validate finds a key by its 8-char prefix, bcrypt-verifies the full key,
// checks expiry and enabled status, and returns the key record on success.
func (m *Manager) Validate(ctx context.Context, rawKey string) (*APIKey, error) {
	if len(rawKey) < 8 {
		return nil, fmt.Errorf("invalid key format")
	}
	prefix := rawKey[:8]

	rows, err := m.pool.Query(ctx, `
		SELECT id, name, key_prefix, key_hash,
		       COALESCE(user_id::text,''), COALESCE(role,'analyst'), COALESCE(scopes,'{}'),
		       expires_at, last_used, enabled, created_at
		FROM api_keys
		WHERE key_prefix = $1 AND enabled = true
		  AND (expires_at IS NULL OR expires_at > NOW())`,
		prefix)
	if err != nil {
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyPrefix, &k.KeyHash,
			&k.UserID, &k.Role, &k.Scopes,
			&k.ExpiresAt, &k.LastUsed, &k.Enabled, &k.CreatedAt,
		); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(k.KeyHash), []byte(rawKey)) == nil {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("invalid or expired api key")
}

// List returns all API keys for a given user (without key_hash).
func (m *Manager) List(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT id, name, key_prefix,
		       COALESCE(user_id::text,''), COALESCE(role,'analyst'), COALESCE(scopes,'{}'),
		       expires_at, last_used, enabled, created_at
		FROM api_keys
		WHERE user_id = $1::uuid
		ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		k := &APIKey{}
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyPrefix,
			&k.UserID, &k.Role, &k.Scopes,
			&k.ExpiresAt, &k.LastUsed, &k.Enabled, &k.CreatedAt,
		); err != nil {
			continue
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []*APIKey{}
	}
	return keys, nil
}

// ListAll returns all API keys across all users (admin use).
func (m *Manager) ListAll(ctx context.Context) ([]*APIKey, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT id, name, key_prefix,
		       COALESCE(user_id::text,''), COALESCE(role,'analyst'), COALESCE(scopes,'{}'),
		       expires_at, last_used, enabled, created_at
		FROM api_keys
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to list all api keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		k := &APIKey{}
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyPrefix,
			&k.UserID, &k.Role, &k.Scopes,
			&k.ExpiresAt, &k.LastUsed, &k.Enabled, &k.CreatedAt,
		); err != nil {
			continue
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []*APIKey{}
	}
	return keys, nil
}

// Revoke disables an API key by ID.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	tag, err := m.pool.Exec(ctx,
		"UPDATE api_keys SET enabled = false WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

// UpdateLastUsed records the current timestamp for the given key (best-effort, non-blocking).
func (m *Manager) UpdateLastUsed(ctx context.Context, id string) {
	go func() {
		if _, err := m.pool.Exec(context.Background(),
			"UPDATE api_keys SET last_used = NOW() WHERE id = $1", id); err != nil {
			slog.Debug("failed to update api key last_used", "id", id, "error", err)
		}
	}()
}
