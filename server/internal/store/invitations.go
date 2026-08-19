package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// InvitationStore handles user invitation database operations.
type InvitationStore struct {
	pool *pgxpool.Pool
}

func NewInvitationStore(db *DB) *InvitationStore {
	return &InvitationStore{pool: db.Pool()}
}

// Invitation mirrors the user_invitations table.
type Invitation struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	TenantID   string     `json:"tenant_id,omitempty"`
	InvitedBy  string     `json:"invited_by,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Create creates a new invitation. Returns the raw (unhashed) token.
func (s *InvitationStore) Create(ctx context.Context, email, role, tenantID, invitedByID string) (string, error) {
	// Generate 32-byte random token, hex-encoded
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("トークンの生成に失敗しました: %w", err)
	}
	rawToken := hex.EncodeToString(raw)

	// bcrypt-hash for storage
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("トークンのハッシュ化に失敗しました: %w", err)
	}

	var tenantParam interface{}
	if tenantID != "" {
		tenantParam = tenantID
	}

	var invitedByParam interface{}
	if invitedByID != "" {
		invitedByParam = invitedByID
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_invitations (email, role, tenant_id, token_hash, invited_by)
		VALUES ($1, $2, $3, $4, $5)`,
		email, role, tenantParam, string(hash), invitedByParam,
	)
	if err != nil {
		return "", fmt.Errorf("招待の作成に失敗しました: %w", err)
	}

	return rawToken, nil
}

// FindByToken looks up a pending (non-accepted, non-expired) invitation by raw token.
func (s *InvitationStore) FindByToken(ctx context.Context, rawToken string) (*Invitation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, role, COALESCE(tenant_id::text, ''),
		       COALESCE(invited_by::text, ''),
		       expires_at, accepted_at, created_at, token_hash
		FROM user_invitations
		WHERE accepted_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("招待の検索に失敗しました: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var inv Invitation
		var tokenHash string
		if err := rows.Scan(
			&inv.ID, &inv.Email, &inv.Role, &inv.TenantID, &inv.InvitedBy,
			&inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt, &tokenHash,
		); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(rawToken)) == nil {
			return &inv, nil
		}
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("招待が見つかりません。期限切れか無効なトークンです")
}

// Accept marks an invitation as accepted by setting accepted_at.
func (s *InvitationStore) Accept(ctx context.Context, invitationID string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE user_invitations SET accepted_at = NOW() WHERE id = $1",
		invitationID,
	)
	return err
}

// ListPending returns all pending (non-accepted, non-expired) invitations.
func (s *InvitationStore) ListPending(ctx context.Context) ([]Invitation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, role, COALESCE(tenant_id::text, ''),
		       COALESCE(invited_by::text, ''),
		       expires_at, accepted_at, created_at
		FROM user_invitations
		WHERE accepted_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invitations []Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(
			&inv.ID, &inv.Email, &inv.Role, &inv.TenantID, &inv.InvitedBy,
			&inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
		); err != nil {
			continue
		}
		invitations = append(invitations, inv)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if invitations == nil {
		invitations = []Invitation{}
	}
	return invitations, nil
}

// Delete removes an invitation by ID (revoke).
func (s *InvitationStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM user_invitations WHERE id = $1", id)
	return err
}
